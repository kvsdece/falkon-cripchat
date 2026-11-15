use core::time::Duration;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::FalkonError;

pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_PLAINTEXT_FRAME_LEN: usize = 32_768;
pub const PADDING_BUCKET_BYTES: usize = 256;

pub type MessageId = [u8; 16];
pub type PeerId = [u8; 16];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryRetention {
    Never,
    Secs5,
    Secs15,
    Secs60,
}

impl HistoryRetention {
    pub fn as_duration(self) -> Option<Duration> {
        match self {
            Self::Never => None,
            Self::Secs5 => Some(Duration::from_secs(5)),
            Self::Secs15 => Some(Duration::from_secs(15)),
            Self::Secs60 => Some(Duration::from_secs(60)),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Never => "Nao limpar",
            Self::Secs5 => "5s",
            Self::Secs15 => "15s",
            Self::Secs60 => "60s",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerSummary {
    pub id: PeerId,
    pub nick: String,
    pub fingerprint: String,
    pub is_host: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ChatPayload {
    pub msg_id: MessageId,
    pub sender_id: PeerId,
    pub sender_nick: String,
    pub body: String,
    pub sent_unix_secs: u64,
}

impl core::fmt::Debug for ChatPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChatPayload")
            .field("msg_id", &self.msg_id)
            .field("sender_nick", &self.sender_nick)
            .field("body", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireMessage {
    JoinRequest {
        nick: String,
    },
    VoteRequest {
        candidate_id: PeerId,
        nick: String,
        fingerprint: String,
    },
    VoteResponse {
        candidate_id: PeerId,
        allow_entry: bool,
        share_history: bool,
    },
    JoinDecision {
        accepted: bool,
        history_shared: bool,
        retention: HistoryRetention,
        reason: Option<String>,
    },
    HistorySync {
        messages: Vec<ChatPayload>,
    },
    Chat(ChatPayload),
    PeerList {
        peers: Vec<PeerSummary>,
    },
    NickUpdate {
        new_nick: String,
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireEnvelope {
    pub version: u8,
    pub message: WireMessage,
}

impl WireEnvelope {
    pub fn new(message: WireMessage) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message,
        }
    }
}

pub fn encode_padded_envelope(envelope: &WireEnvelope) -> Result<Zeroizing<Vec<u8>>, FalkonError> {
    let raw = Zeroizing::new(
        postcard::to_allocvec(envelope).map_err(|e| FalkonError::Codec(e.to_string()))?,
    );

    if raw.len() > MAX_PLAINTEXT_FRAME_LEN {
        return Err(FalkonError::FrameTooLarge {
            len: raw.len(),
            max: MAX_PLAINTEXT_FRAME_LEN,
        });
    }

    let unpadded_total = 4 + raw.len();
    let padded_total = unpadded_total.div_ceil(PADDING_BUCKET_BYTES) * PADDING_BUCKET_BYTES;

    let mut out = Zeroizing::new(vec![0u8; padded_total]);
    let len_u32 =
        u32::try_from(raw.len()).map_err(|_| FalkonError::InvalidInput("tamanho excede u32"))?;
    out[..4].copy_from_slice(&len_u32.to_be_bytes());
    out[4..4 + raw.len()].copy_from_slice(&raw);

    Ok(out)
}

pub fn decode_padded_envelope(padded: &[u8]) -> Result<WireEnvelope, FalkonError> {
    if padded.len() < 4 || padded.len() > MAX_PLAINTEXT_FRAME_LEN + PADDING_BUCKET_BYTES {
        return Err(FalkonError::InvalidInput("envelope com tamanho invalido"));
    }

    let len_bytes: [u8; 4] = padded[..4]
        .try_into()
        .map_err(|_| FalkonError::InvalidInput("cabecalho incompleto"))?;
    let payload_len = usize::try_from(u32::from_be_bytes(len_bytes))
        .map_err(|_| FalkonError::InvalidInput("tamanho invalido"))?;

    if payload_len == 0 || payload_len > MAX_PLAINTEXT_FRAME_LEN || 4 + payload_len > padded.len() {
        return Err(FalkonError::InvalidInput(
            "comprimento de payload inconsistente",
        ));
    }

    let envelope: WireEnvelope = postcard::from_bytes(&padded[4..4 + payload_len])
        .map_err(|e| FalkonError::Codec(e.to_string()))?;

    if envelope.version != PROTOCOL_VERSION {
        return Err(FalkonError::InvalidInput(
            "versao de protocolo nao suportada",
        ));
    }

    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padded_envelope_roundtrip_aligns_to_bucket() -> Result<(), FalkonError> {
        let env = WireEnvelope::new(WireMessage::VoteResponse {
            candidate_id: [9u8; 16],
            allow_entry: true,
            share_history: false,
        });

        let encoded = encode_padded_envelope(&env)?;
        assert_eq!(encoded.len() % PADDING_BUCKET_BYTES, 0);

        let decoded = decode_padded_envelope(&encoded)?;
        assert_eq!(decoded, env);
        Ok(())
    }
}
