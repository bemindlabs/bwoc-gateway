//! End-to-end body encryption — a **client-side** concern, by design.
//!
//! The gateway routes on the cleartext `recipient` header and treats the
//! envelope `body` as opaque. This module lets a sender encrypt the body *to
//! the recipient's key* so the relay (and any peer gateway it federates
//! through) carries only ciphertext it cannot read.
//!
//! Keying reuses the agent's existing **ed25519 identity** — no second keypair
//! to distribute. We derive an x25519 keypair from it using the standard
//! libsodium conversion (`crypto_sign_ed25519_*_to_curve25519`):
//!
//! - public:  the ed25519 verifying key's Edwards point → Montgomery `u`.
//! - secret:  `clamp(SHA-512(ed25519_seed)[..32])`.
//!
//! and seal with an anonymous-sender **sealed box** (X25519 + XSalsa20-Poly1305),
//! so only the holder of the recipient's private key can open it.

use crypto_box::{aead::OsRng, PublicKey, SecretKey};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("malformed ed25519 key")]
    BadKey,
    #[error("seal failed")]
    Seal,
    #[error("open failed (wrong key or corrupt ciphertext)")]
    Open,
}

/// Derive the recipient's x25519 **public** key from their ed25519 verifying key.
fn x25519_public_from_ed25519(vk: &VerifyingKey) -> Result<PublicKey, CryptoError> {
    let edwards = CompressedEdwardsY(vk.to_bytes())
        .decompress()
        .ok_or(CryptoError::BadKey)?;
    Ok(PublicKey::from(edwards.to_montgomery().to_bytes()))
}

/// Derive our x25519 **secret** key from our ed25519 signing key.
fn x25519_secret_from_ed25519(sk: &SigningKey) -> SecretKey {
    // The ed25519 *seed* (the 32-byte private scalar source), hashed and clamped
    // exactly as libsodium does, yields the matching x25519 secret.
    let hash = Sha512::digest(sk.to_bytes());
    let mut s = [0u8; 32];
    s.copy_from_slice(&hash[..32]);
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
    SecretKey::from(s)
}

/// Seal `plaintext` to a recipient identified by their hex ed25519 public key.
/// Returns hex ciphertext suitable for an envelope `body` field. Anonymous
/// sender — the recipient learns nothing about *who* sealed it from the box
/// alone (the envelope's signed `sender` provides authenticated provenance).
pub fn seal_to_hex(recipient_ed25519_hex: &str, plaintext: &[u8]) -> Result<String, CryptoError> {
    let vk = verifying_key_from_hex(recipient_ed25519_hex)?;
    let recipient = x25519_public_from_ed25519(&vk)?;
    let sealed = recipient
        .seal(&mut OsRng, plaintext)
        .map_err(|_| CryptoError::Seal)?;
    Ok(hex::encode(sealed))
}

/// Open hex ciphertext sealed to our ed25519 identity.
pub fn open_from_hex(
    our_ed25519: &SigningKey,
    ciphertext_hex: &str,
) -> Result<Vec<u8>, CryptoError> {
    let ct = hex::decode(ciphertext_hex).map_err(|_| CryptoError::Open)?;
    let secret = x25519_secret_from_ed25519(our_ed25519);
    secret.unseal(&ct).map_err(|_| CryptoError::Open)
}

fn verifying_key_from_hex(hex_key: &str) -> Result<VerifyingKey, CryptoError> {
    let bytes: [u8; 32] = hex::decode(hex_key)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(CryptoError::BadKey)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| CryptoError::BadKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn roundtrip_seal_open() {
        let recipient = signing_key(5);
        let recipient_pub_hex = hex::encode(recipient.verifying_key().to_bytes());

        let msg = b"the relay must not read this";
        let sealed = seal_to_hex(&recipient_pub_hex, msg).unwrap();
        assert_ne!(sealed.as_bytes(), msg); // it's ciphertext

        let opened = open_from_hex(&recipient, &sealed).unwrap();
        assert_eq!(opened, msg);
    }

    #[test]
    fn wrong_recipient_cannot_open() {
        let recipient = signing_key(5);
        let attacker = signing_key(9);
        let recipient_pub_hex = hex::encode(recipient.verifying_key().to_bytes());

        let sealed = seal_to_hex(&recipient_pub_hex, b"secret").unwrap();
        assert!(open_from_hex(&attacker, &sealed).is_err());
    }

    #[test]
    fn malformed_key_is_rejected() {
        assert!(seal_to_hex("not-hex", b"x").is_err());
        assert!(seal_to_hex(&"ab".repeat(10), b"x").is_err()); // wrong length
    }
}
