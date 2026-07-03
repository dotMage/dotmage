//! Invitation sealing (spec K.1): AK sealed with a key that lives only
//! inside the one-time invite token — the server never sees it.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use rand::RngCore;

use crate::envelope::{EnvelopeError, WrappedAk, AK_LEN};

const INVITE_AAD: &[u8] = b"dotmage-invite-v1";
const NONCE_LEN: usize = 24;

/// Seal AK with the invite key K (spec K.1).
pub fn seal_ak_invite(k: &[u8; AK_LEN], ak: &[u8; AK_LEN]) -> Result<WrappedAk, EnvelopeError> {
    let cipher = XChaCha20Poly1305::new(k.into());

    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: ak.as_slice(),
                aad: INVITE_AAD,
            },
        )
        .map_err(|e| EnvelopeError::Encryption(e.to_string()))?;

    Ok(WrappedAk { nonce, ciphertext })
}

/// Unseal AK with the invite key K (spec K.2).
pub fn unseal_ak_invite(
    k: &[u8; AK_LEN],
    sealed: &WrappedAk,
) -> Result<[u8; AK_LEN], EnvelopeError> {
    let cipher = XChaCha20Poly1305::new(k.into());

    let plaintext = cipher
        .decrypt(
            (&sealed.nonce).into(),
            Payload {
                msg: sealed.ciphertext.as_slice(),
                aad: INVITE_AAD,
            },
        )
        .map_err(|_| {
            EnvelopeError::Decryption("AEAD authentication failed (bad invite token)".into())
        })?;

    plaintext
        .try_into()
        .map_err(|_| EnvelopeError::Decryption("unexpected AK length".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let k = [7u8; 32];
        let ak = [9u8; 32];
        let sealed = seal_ak_invite(&k, &ak).unwrap();
        assert_eq!(unseal_ak_invite(&k, &sealed).unwrap(), ak);
        let wrong = [8u8; 32];
        assert!(unseal_ak_invite(&wrong, &sealed).is_err());
    }

    /// Spec K.3 golden vector (fixed nonce path exercised via low-level cipher
    /// in tests/team_vectors.rs; here we pin AAD compatibility).
    #[test]
    fn spec_k3_vector_unseals() {
        let k = [0x01u8; 32];
        let sealed = WrappedAk {
            nonce: [0x03u8; 24],
            ciphertext: (0..48)
                .map(|i| {
                    u8::from_str_radix(
                        &"4c020d73f23dd0c3e9dfa73e4f35df0115d526a098b9ef1bfb14f56179163dfd035ad4c5c97ed819cae664562ada2dc3"[i * 2..i * 2 + 2],
                        16,
                    )
                    .unwrap()
                })
                .collect(),
        };
        assert_eq!(unseal_ak_invite(&k, &sealed).unwrap(), [0x02u8; 32]);
    }
}
