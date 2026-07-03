//! Golden vectors for spec Appendix K.3 (invitation sealing, recovery AAD).
//! Byte-for-byte in sync with spec.md — do not regenerate casually.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const K: [u8; 32] = [0x01; 32];
const AK: [u8; 32] = [0x02; 32];
const NONCE: [u8; 24] = [0x03; 24];

#[test]
fn spec_k3_invite_seal_vector() {
    let cipher = XChaCha20Poly1305::new((&K).into());
    let sealed = cipher
        .encrypt(
            (&NONCE).into(),
            Payload {
                msg: &AK,
                aad: b"dotmage-invite-v1",
            },
        )
        .unwrap();
    assert_eq!(
        hex(&sealed),
        "4c020d73f23dd0c3e9dfa73e4f35df0115d526a098b9ef1bfb14f56179163dfd\
         035ad4c5c97ed819cae664562ada2dc3"
            .replace(char::is_whitespace, "")
    );
}

#[test]
fn spec_k3_recovery_aad_vector() {
    let cipher = XChaCha20Poly1305::new((&K).into());
    let ct = cipher
        .encrypt(
            (&NONCE).into(),
            Payload {
                msg: &AK,
                aad: b"dotmage-ak-rc-v1",
            },
        )
        .unwrap();
    assert_eq!(
        hex(&ct),
        "4c020d73f23dd0c3e9dfa73e4f35df0115d526a098b9ef1bfb14f56179163dfd\
         3f52d33f58cd99a01ba8b6470f05cd6a"
            .replace(char::is_whitespace, "")
    );
}

/// AAD binding: the same sealed blob must NOT open under a different context.
#[test]
fn seal_is_aad_bound() {
    let cipher = XChaCha20Poly1305::new((&K).into());
    let sealed = cipher
        .encrypt(
            (&NONCE).into(),
            Payload {
                msg: &AK,
                aad: b"dotmage-invite-v1",
            },
        )
        .unwrap();
    assert!(cipher
        .decrypt(
            (&NONCE).into(),
            Payload {
                msg: sealed.as_slice(),
                aad: b"dotmage-ak-rc-v1",
            },
        )
        .is_err());
}
