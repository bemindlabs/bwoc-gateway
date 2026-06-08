//! Signed-challenge authentication. The agent's ed25519 keypair IS the login —
//! no passwords, no gateway-side accounts. The gateway proves the connecting
//! client controls the private key for the public key it presented, then trusts
//! the framework's higher layers (Kalyāṇamitta-7 authorization) to decide what
//! that identity may do.

use crate::wire::ServerFrame;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("no ClientHello frame")]
    NoHello,
    #[error("malformed ClientHello")]
    BadHello,
    #[error("malformed public key")]
    BadKey,
    #[error("no challenge response")]
    NoResponse,
    #[error("malformed challenge response")]
    BadResponse,
    #[error("signature verification failed")]
    BadSignature,
    #[error("transport error")]
    Transport,
}

/// A per-connection challenge: a random nonce bound to the client's claimed key.
pub struct Challenge {
    nonce: [u8; 32],
    key: VerifyingKey,
}

#[derive(Deserialize)]
struct ChallengeResponse {
    /// Hex ed25519 signature (64 bytes) over the nonce.
    signature: String,
}

impl Challenge {
    /// Build a fresh challenge for the presented hex public key.
    pub fn new(pubkey_hex: &str) -> Result<Self, AuthError> {
        let key_bytes: [u8; 32] = hex::decode(pubkey_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(AuthError::BadKey)?;
        let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| AuthError::BadKey)?;
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).map_err(|_| AuthError::Transport)?;
        Ok(Self { nonce, key })
    }

    /// The challenge frame to send to the client (nonce as hex).
    pub fn frame_json(&self, agent_id: &str) -> String {
        ServerFrame::Challenge {
            agent_id: agent_id.to_string(),
            nonce: hex::encode(self.nonce),
        }
        .to_json()
    }

    /// Verify the client's signature over the nonce.
    pub fn verify_response(&self, response_json: &str) -> Result<(), AuthError> {
        let resp: ChallengeResponse =
            serde_json::from_str(response_json).map_err(|_| AuthError::BadResponse)?;
        let sig_bytes: [u8; 64] = hex::decode(&resp.signature)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(AuthError::BadResponse)?;
        let sig = Signature::from_bytes(&sig_bytes);
        self.key
            .verify(&self.nonce, &sig)
            .map_err(|_| AuthError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn valid_signature_authenticates() {
        let mut seed = [7u8; 32];
        seed[0] = 1;
        let sk = SigningKey::from_bytes(&seed);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        let ch = Challenge::new(&pk_hex).unwrap();
        let sig = sk.sign(&ch.nonce);
        let resp = format!(r#"{{"signature":"{}"}}"#, hex::encode(sig.to_bytes()));
        assert!(ch.verify_response(&resp).is_ok());
    }

    #[test]
    fn wrong_key_is_rejected() {
        let sk = SigningKey::from_bytes(&[2u8; 32]);
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        let ch = Challenge::new(&pk_hex).unwrap();
        let sig = attacker.sign(&ch.nonce); // signed by the wrong key
        let resp = format!(r#"{{"signature":"{}"}}"#, hex::encode(sig.to_bytes()));
        assert!(matches!(
            ch.verify_response(&resp),
            Err(AuthError::BadSignature)
        ));
    }
}
