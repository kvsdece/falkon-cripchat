use core::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::FalkonError;

pub const NOISE_PATTERN: &str = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s";
pub const NOISE_PROLOGUE: &[u8] = b"FALKON-PROTO-V1";
pub const MAX_NOISE_MSG_LEN: usize = 65_535;
pub const NOISE_TAG_LEN: usize = 16;
pub const MIN_ROOM_SECRET_LEN: usize = 12;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RoomSecret(String);

impl RoomSecret {
    pub fn new(secret: String) -> Result<Self, FalkonError> {
        if secret.len() < MIN_ROOM_SECRET_LEN {
            return Err(FalkonError::InvalidInput(
                "segredo da sala deve ter ao menos 12 bytes/caracteres",
            ));
        }
        if secret.bytes().all(|b| Some(b) == secret.bytes().next()) {
            return Err(FalkonError::InvalidInput(
                "segredo da sala nao pode repetir o mesmo caractere",
            ));
        }
        Ok(Self(secret))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for RoomSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RoomSecret([REDACTED])")
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IdentityKeypair {
    private: Vec<u8>,
    public: Vec<u8>,
}

impl IdentityKeypair {
    pub fn generate() -> Result<Self, FalkonError> {
        let params: snow::params::NoiseParams = NOISE_PATTERN
            .parse()
            .map_err(|e| FalkonError::Crypto(format!("parametros Noise invalidos: {e}")))?;

        let kp = snow::Builder::new(params)
            .generate_keypair()
            .map_err(|e| FalkonError::Crypto(format!("falha ao gerar par de chaves: {e}")))?;

        Ok(Self {
            private: kp.private,
            public: kp.public,
        })
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    pub fn private_key(&self) -> &[u8] {
        &self.private
    }

    pub fn fingerprint(&self) -> String {
        fingerprint_from_pubkey(&self.public)
    }

    pub fn full_fingerprint(&self) -> String {
        full_fingerprint_from_pubkey(&self.public)
    }
}

impl fmt::Debug for IdentityKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IdentityKeypair(fp={})", self.fingerprint())
    }
}

/// Gera fingerprint de 128 bits (16 primeiros bytes do SHA-256).
pub fn fingerprint_from_pubkey(pubkey: &[u8]) -> String {
    let d = Sha256::digest(pubkey);
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}",
        d[0],
        d[1],
        d[2],
        d[3],
        d[4],
        d[5],
        d[6],
        d[7],
        d[8],
        d[9],
        d[10],
        d[11],
        d[12],
        d[13],
        d[14],
        d[15]
    )
}

/// Gera fingerprint completo de 256 bits (SHA-256 integral em hex).
pub fn full_fingerprint_from_pubkey(pubkey: &[u8]) -> String {
    let d = Sha256::digest(pubkey);
    let mut out = String::with_capacity(64);
    for byte in d {
        out.push_str(&format!("{byte:02X}"));
    }
    out
}

pub fn peer_id_from_pubkey(pubkey: &[u8]) -> [u8; 16] {
    let digest = Sha256::digest(pubkey);
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

pub fn random_bytes<const N: usize>() -> Result<[u8; N], FalkonError> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf)
        .map_err(|e| FalkonError::Crypto(format!("falha ao ler entropia do SO: {e}")))?;
    Ok(buf)
}

pub fn derive_room_psk(
    secret: &RoomSecret,
    room_salt: &[u8; 16],
) -> Result<Zeroizing<[u8; 32]>, FalkonError> {
    let mut full_salt = [0u8; 32];
    full_salt[..16].copy_from_slice(b"FALKON_PSK_V1_00");
    full_salt[16..].copy_from_slice(room_salt);

    let params = Params::new(19_456, 2, 1, Some(32))
        .map_err(|e| FalkonError::Crypto(format!("parametros Argon2 invalidos: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(secret.as_bytes(), &full_salt, &mut *out)
        .map_err(|e| FalkonError::Crypto(format!("falha Argon2id: {e}")))?;

    Ok(out)
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

pub fn build_initiator_handshake(
    identity: &IdentityKeypair,
    psk: &[u8; 32],
) -> Result<snow::HandshakeState, FalkonError> {
    let params: snow::params::NoiseParams = NOISE_PATTERN
        .parse()
        .map_err(|e| FalkonError::Crypto(format!("parametros Noise: {e}")))?;

    snow::Builder::new(params)
        .prologue(NOISE_PROLOGUE)
        .map_err(|e| FalkonError::Crypto(format!("prologue: {e}")))?
        .local_private_key(identity.private_key())
        .map_err(|e| FalkonError::Crypto(format!("local key: {e}")))?
        .psk(3, psk)
        .map_err(|e| FalkonError::Crypto(format!("psk: {e}")))?
        .build_initiator()
        .map_err(|e| FalkonError::Crypto(format!("build initiator: {e}")))
}

pub fn build_responder_handshake(
    identity: &IdentityKeypair,
    psk: &[u8; 32],
) -> Result<snow::HandshakeState, FalkonError> {
    let params: snow::params::NoiseParams = NOISE_PATTERN
        .parse()
        .map_err(|e| FalkonError::Crypto(format!("parametros Noise: {e}")))?;

    snow::Builder::new(params)
        .prologue(NOISE_PROLOGUE)
        .map_err(|e| FalkonError::Crypto(format!("prologue: {e}")))?
        .local_private_key(identity.private_key())
        .map_err(|e| FalkonError::Crypto(format!("local key: {e}")))?
        .psk(3, psk)
        .map_err(|e| FalkonError::Crypto(format!("psk: {e}")))?
        .build_responder()
        .map_err(|e| FalkonError::Crypto(format!("build responder: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_secret_enforces_min_length_and_variation() {
        assert!(RoomSecret::new("123456".to_owned()).is_err());
        assert!(RoomSecret::new("aaaaaaaaaaaa".to_owned()).is_err());
        assert!(RoomSecret::new("frase-segura-falkon".to_owned()).is_ok());
    }

    #[test]
    fn fingerprint_lengths_are_128_and_256_bits() -> Result<(), FalkonError> {
        let id = IdentityKeypair::generate()?;
        assert_eq!(id.fingerprint().len(), 35); // 32 hex + 3 hifens (128 bits)
        assert_eq!(id.full_fingerprint().len(), 64); // 64 hex (256 bits)
        Ok(())
    }

    #[test]
    fn noise_xxpsk3_handshake_succeeds_and_rejects_wrong_psk() -> Result<(), FalkonError> {
        let salt = [0x42u8; 16];
        let secret_ok = RoomSecret::new("segredo-forte-falkon".to_owned())?;
        let secret_bad = RoomSecret::new("segredo-errado-12345".to_owned())?;

        let psk_ok = derive_room_psk(&secret_ok, &salt)?;
        let psk_bad = derive_room_psk(&secret_bad, &salt)?;

        let alice_id = IdentityKeypair::generate()?;
        let bob_id = IdentityKeypair::generate()?;

        let mut alice = build_initiator_handshake(&alice_id, &psk_ok)?;
        let mut bob = build_responder_handshake(&bob_id, &psk_ok)?;

        let mut buf = [0u8; 4096];
        let mut out = [0u8; 4096];

        let n = alice
            .write_message(&[], &mut buf)
            .map_err(|e| FalkonError::Crypto(e.to_string()))?;
        bob.read_message(&buf[..n], &mut out)
            .map_err(|e| FalkonError::Crypto(e.to_string()))?;

        let n = bob
            .write_message(&[], &mut buf)
            .map_err(|e| FalkonError::Crypto(e.to_string()))?;
        alice
            .read_message(&buf[..n], &mut out)
            .map_err(|e| FalkonError::Crypto(e.to_string()))?;

        let n = alice
            .write_message(&[], &mut buf)
            .map_err(|e| FalkonError::Crypto(e.to_string()))?;
        bob.read_message(&buf[..n], &mut out)
            .map_err(|e| FalkonError::Crypto(e.to_string()))?;

        assert!(alice.is_handshake_finished());
        assert!(bob.is_handshake_finished());

        let alice_sees_bob = alice
            .get_remote_static()
            .ok_or(FalkonError::InvalidState("chave remota ausente"))?;
        assert!(constant_time_eq(alice_sees_bob, bob_id.public_key()));

        let mut mallory = build_initiator_handshake(&alice_id, &psk_bad)?;
        let mut bob2 = build_responder_handshake(&bob_id, &psk_ok)?;

        let n = mallory
            .write_message(&[], &mut buf)
            .map_err(|e| FalkonError::Crypto(e.to_string()))?;
        bob2.read_message(&buf[..n], &mut out)
            .map_err(|e| FalkonError::Crypto(e.to_string()))?;

        let n = bob2
            .write_message(&[], &mut buf)
            .map_err(|e| FalkonError::Crypto(e.to_string()))?;
        mallory
            .read_message(&buf[..n], &mut out)
            .map_err(|e| FalkonError::Crypto(e.to_string()))?;

        let n = mallory
            .write_message(&[], &mut buf)
            .map_err(|e| FalkonError::Crypto(e.to_string()))?;
        let res = bob2.read_message(&buf[..n], &mut out);
        assert!(res.is_err());

        Ok(())
    }
}
