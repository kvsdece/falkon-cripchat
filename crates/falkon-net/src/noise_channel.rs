use core::time::Duration;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use zeroize::Zeroizing;

use falkon_core::crypto::{
    IdentityKeypair, MAX_NOISE_MSG_LEN, NOISE_TAG_LEN, build_initiator_handshake,
    build_responder_handshake, fingerprint_from_pubkey, peer_id_from_pubkey,
};
use falkon_core::error::FalkonError;
use falkon_core::protocol::{WireEnvelope, decode_padded_envelope, encode_padded_envelope};

use crate::framing::{read_frame, read_frame_with_timeout, read_handshake_frame, write_frame};

pub struct EncryptedChannel<S> {
    stream: S,
    transport: snow::TransportState,
    remote_fingerprint: String,
    remote_peer_id: [u8; 16],
}

pub struct ChannelSender<S> {
    writer: WriteHalf<S>,
    transport: Arc<Mutex<snow::TransportState>>,
}

pub struct ChannelReceiver<S> {
    reader: ReadHalf<S>,
    transport: Arc<Mutex<snow::TransportState>>,
    remote_fingerprint: String,
    remote_peer_id: [u8; 16],
}

impl<S: AsyncRead + AsyncWrite + Unpin> EncryptedChannel<S> {
    pub async fn connect_initiator(
        mut stream: S,
        identity: &IdentityKeypair,
        psk: &[u8; 32],
    ) -> Result<Self, FalkonError> {
        let mut hs = build_initiator_handshake(identity, psk)?;
        let mut out_buf = Zeroizing::new(vec![0u8; 1024]);
        let mut plain_buf = Zeroizing::new(vec![0u8; 1024]);

        let n = hs
            .write_message(&[], &mut out_buf)
            .map_err(|e| FalkonError::Crypto(e.to_string()))?;
        write_frame(&mut stream, &out_buf[..n]).await?;

        let msg2 = read_handshake_frame(&mut stream).await?;
        let _ = hs
            .read_message(&msg2, &mut plain_buf)
            .map_err(|e| FalkonError::Crypto(e.to_string()))?;

        let n = hs
            .write_message(&[], &mut out_buf)
            .map_err(|e| FalkonError::Crypto(e.to_string()))?;
        write_frame(&mut stream, &out_buf[..n]).await?;

        let remote_pub = hs
            .get_remote_static()
            .ok_or(FalkonError::InvalidState("peer sem chave estatica"))?;
        let remote_fingerprint = fingerprint_from_pubkey(remote_pub);
        let remote_peer_id = peer_id_from_pubkey(remote_pub);

        let transport = hs
            .into_transport_mode()
            .map_err(|e| FalkonError::Crypto(e.to_string()))?;

        Ok(Self {
            stream,
            transport,
            remote_fingerprint,
            remote_peer_id,
        })
    }

    pub async fn accept_responder(
        mut stream: S,
        identity: &IdentityKeypair,
        psk: &[u8; 32],
    ) -> Result<Self, FalkonError> {
        let mut hs = build_responder_handshake(identity, psk)?;
        let mut out_buf = Zeroizing::new(vec![0u8; 1024]);
        let mut plain_buf = Zeroizing::new(vec![0u8; 1024]);

        let msg1 = read_handshake_frame(&mut stream).await?;
        let _ = hs
            .read_message(&msg1, &mut plain_buf)
            .map_err(|e| FalkonError::Crypto(e.to_string()))?;

        let n = hs
            .write_message(&[], &mut out_buf)
            .map_err(|e| FalkonError::Crypto(e.to_string()))?;
        write_frame(&mut stream, &out_buf[..n]).await?;

        let msg3 = read_handshake_frame(&mut stream).await?;
        let _ = hs
            .read_message(&msg3, &mut plain_buf)
            .map_err(|e| FalkonError::Crypto(e.to_string()))?;

        let remote_pub = hs
            .get_remote_static()
            .ok_or(FalkonError::InvalidState("peer sem chave estatica"))?;
        let remote_fingerprint = fingerprint_from_pubkey(remote_pub);
        let remote_peer_id = peer_id_from_pubkey(remote_pub);

        let transport = hs
            .into_transport_mode()
            .map_err(|e| FalkonError::Crypto(e.to_string()))?;

        Ok(Self {
            stream,
            transport,
            remote_fingerprint,
            remote_peer_id,
        })
    }

    pub fn remote_fingerprint(&self) -> &str {
        &self.remote_fingerprint
    }

    pub fn remote_peer_id(&self) -> [u8; 16] {
        self.remote_peer_id
    }

    pub fn into_split(self) -> (ChannelSender<S>, ChannelReceiver<S>) {
        let (reader, writer) = tokio::io::split(self.stream);
        let transport = Arc::new(Mutex::new(self.transport));
        (
            ChannelSender {
                writer,
                transport: Arc::clone(&transport),
            },
            ChannelReceiver {
                reader,
                transport,
                remote_fingerprint: self.remote_fingerprint,
                remote_peer_id: self.remote_peer_id,
            },
        )
    }

    pub async fn send_envelope(&mut self, envelope: &WireEnvelope) -> Result<(), FalkonError> {
        let padded = encode_padded_envelope(envelope)?;
        if padded.len() + NOISE_TAG_LEN > MAX_NOISE_MSG_LEN {
            return Err(FalkonError::FrameTooLarge {
                len: padded.len() + NOISE_TAG_LEN,
                max: MAX_NOISE_MSG_LEN,
            });
        }

        let mut encrypted = vec![0u8; padded.len() + NOISE_TAG_LEN];
        let n = self
            .transport
            .write_message(&padded, &mut encrypted)
            .map_err(|e| FalkonError::Crypto(e.to_string()))?;

        write_frame(&mut self.stream, &encrypted[..n]).await
    }

    pub async fn recv_envelope(&mut self) -> Result<WireEnvelope, FalkonError> {
        let encrypted = read_frame(&mut self.stream).await?;
        let mut decrypted = Zeroizing::new(vec![0u8; encrypted.len()]);
        let n = self
            .transport
            .read_message(&encrypted, &mut decrypted)
            .map_err(|e| FalkonError::Crypto(e.to_string()))?;

        decode_padded_envelope(&decrypted[..n])
    }
}

impl<S: AsyncWrite + Unpin> ChannelSender<S> {
    pub async fn send_envelope(&mut self, envelope: &WireEnvelope) -> Result<(), FalkonError> {
        let padded = encode_padded_envelope(envelope)?;
        if padded.len() + NOISE_TAG_LEN > MAX_NOISE_MSG_LEN {
            return Err(FalkonError::FrameTooLarge {
                len: padded.len() + NOISE_TAG_LEN,
                max: MAX_NOISE_MSG_LEN,
            });
        }

        let mut encrypted = vec![0u8; padded.len() + NOISE_TAG_LEN];
        let n = {
            let mut guard = self
                .transport
                .lock()
                .map_err(|_| FalkonError::InvalidState("mutex Noise corrompido"))?;
            guard
                .write_message(&padded, &mut encrypted)
                .map_err(|e| FalkonError::Crypto(e.to_string()))?
        };

        write_frame(&mut self.writer, &encrypted[..n]).await
    }
}

impl<S: AsyncRead + Unpin> ChannelReceiver<S> {
    pub fn remote_fingerprint(&self) -> &str {
        &self.remote_fingerprint
    }

    pub fn remote_peer_id(&self) -> [u8; 16] {
        self.remote_peer_id
    }

    pub async fn recv_envelope(
        &mut self,
        read_timeout: Duration,
    ) -> Result<WireEnvelope, FalkonError> {
        let encrypted = read_frame_with_timeout(&mut self.reader, read_timeout).await?;
        let mut decrypted = Zeroizing::new(vec![0u8; encrypted.len()]);
        let n = {
            let mut guard = self
                .transport
                .lock()
                .map_err(|_| FalkonError::InvalidState("mutex Noise corrompido"))?;
            guard
                .read_message(&encrypted, &mut decrypted)
                .map_err(|e| FalkonError::Crypto(e.to_string()))?
        };

        decode_padded_envelope(&decrypted[..n])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{DirectTcpTransport, PeerEndpoint, PeerTransport};
    use falkon_core::crypto::{RoomSecret, derive_room_psk};
    use falkon_core::protocol::{HistoryRetention, WireMessage};

    #[tokio::test]
    async fn p2p_loopback_handshake_and_dual_vote_exchange() -> Result<(), FalkonError> {
        let transport = DirectTcpTransport;
        let listener = transport.bind("127.0.0.1:0").await?;
        let endpoint = listener.local_endpoint()?;
        let addr = match endpoint {
            PeerEndpoint::DirectTcp(a) => a.to_string(),
            PeerEndpoint::OnionV3(s) => s,
        };

        let salt = [0xAAu8; 16];
        let psk = derive_room_psk(&RoomSecret::new("falkon-loopback-test".to_owned())?, &salt)?;
        let host_id = IdentityKeypair::generate()?;
        let peer_id = IdentityKeypair::generate()?;

        let host_fp = host_id.fingerprint();
        let peer_fp = peer_id.fingerprint();
        let expected_host_pid = peer_id_from_pubkey(host_id.public_key());
        let psk_host = Zeroizing::new(*psk);

        let host_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut ch = EncryptedChannel::accept_responder(stream, &host_id, &psk_host).await?;
            assert_eq!(ch.remote_fingerprint(), peer_fp);

            let req = ch.recv_envelope().await?;
            assert_eq!(
                req.message,
                WireMessage::JoinRequest {
                    nick: "Clara".to_owned()
                }
            );

            ch.send_envelope(&WireEnvelope::new(WireMessage::JoinDecision {
                accepted: true,
                history_shared: false,
                retention: HistoryRetention::Secs15,
                reason: None,
            }))
            .await?;

            Ok::<(), FalkonError>(())
        });

        let stream = transport.connect(&addr).await?;
        let mut peer_ch = EncryptedChannel::connect_initiator(stream, &peer_id, &psk).await?;
        assert_eq!(peer_ch.remote_fingerprint(), host_fp);
        assert_eq!(peer_ch.remote_peer_id(), expected_host_pid);

        peer_ch
            .send_envelope(&WireEnvelope::new(WireMessage::JoinRequest {
                nick: "Clara".to_owned(),
            }))
            .await?;

        let decision = peer_ch.recv_envelope().await?;
        assert_eq!(
            decision.message,
            WireMessage::JoinDecision {
                accepted: true,
                history_shared: false,
                retention: HistoryRetention::Secs15,
                reason: None,
            }
        );

        host_task
            .await
            .map_err(|e| FalkonError::Io(e.to_string()))??;

        Ok(())
    }
}
