//! DMGF1 file container — carries file metadata INSIDE the encrypted payload.
//!
//! Layout of the plaintext handed to the crypto layer:
//!
//! ```text
//! DMGF1\n
//! {"file_name":"dataSources.xml","format":"text"}\n
//! <raw file bytes>
//! ```
//!
//! The container is used only when metadata must travel (non-env format, or an
//! env file whose name isn't the default `.env`). A plain `.env` is stored raw,
//! exactly as v1 did — full interop with older CLIs on existing apps. The
//! server never sees any of this: metadata is encrypted with the payload.

use serde::{Deserialize, Serialize};

const MAGIC: &[u8] = b"DMGF1\n";
/// Default file name for legacy raw payloads.
pub const DEFAULT_ENV_FILE: &str = ".env";

/// Content format — decides how diff/exec/key-counting treat the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileFormat {
    Env,
    Text,
    Binary,
}

impl FileFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            FileFormat::Env => "env",
            FileFormat::Text => "text",
            FileFormat::Binary => "binary",
        }
    }
}

impl std::str::FromStr for FileFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "env" => Ok(FileFormat::Env),
            "text" => Ok(FileFormat::Text),
            "binary" => Ok(FileFormat::Binary),
            other => Err(format!("unknown format '{other}' (env|text|binary)")),
        }
    }
}

/// File metadata stored inside the container.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileMeta {
    pub file_name: String,
    pub format: FileFormat,
}

impl FileMeta {
    pub fn legacy_env() -> Self {
        Self {
            file_name: DEFAULT_ENV_FILE.into(),
            format: FileFormat::Env,
        }
    }

    /// Raw-payload rule: the exact default `.env` is stored WITHOUT a container
    /// so old CLIs interop on env apps; anything else needs the metadata.
    pub fn needs_container(&self) -> bool {
        !(self.format == FileFormat::Env && self.file_name == DEFAULT_ENV_FILE)
    }
}

/// A decoded payload: metadata + raw file bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct Decoded {
    pub meta: FileMeta,
    /// True when the payload had no container (v1 raw .env).
    pub legacy: bool,
    pub data: Vec<u8>,
}

/// Wrap file bytes in a container when metadata must travel; raw otherwise.
pub fn encode(meta: &FileMeta, data: &[u8]) -> Vec<u8> {
    if !meta.needs_container() {
        return data.to_vec();
    }
    let header = serde_json::to_string(meta).expect("FileMeta serializes");
    let mut out = Vec::with_capacity(MAGIC.len() + header.len() + 1 + data.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(header.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(data);
    out
}

/// Sniff and unwrap a decrypted payload. Never fails: anything that is not a
/// well-formed container is a legacy raw .env (including a pathological .env
/// that merely *starts* with the magic — its second line won't parse as meta).
pub fn decode(plaintext: &[u8]) -> Decoded {
    let legacy = || Decoded {
        meta: FileMeta::legacy_env(),
        legacy: true,
        data: plaintext.to_vec(),
    };

    let Some(rest) = plaintext.strip_prefix(MAGIC) else {
        return legacy();
    };
    let Some(nl) = rest.iter().position(|&b| b == b'\n') else {
        return legacy();
    };
    let Ok(meta) = serde_json::from_slice::<FileMeta>(&rest[..nl]) else {
        return legacy();
    };
    Decoded {
        meta,
        legacy: false,
        data: rest[nl + 1..].to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(name: &str, format: FileFormat) -> FileMeta {
        FileMeta {
            file_name: name.into(),
            format,
        }
    }

    #[test]
    fn roundtrip_text() {
        let m = meta("dataSources.xml", FileFormat::Text);
        let data = b"<xml>secret</xml>";
        let encoded = encode(&m, data);
        assert!(encoded.starts_with(MAGIC));
        let d = decode(&encoded);
        assert!(!d.legacy);
        assert_eq!(d.meta, m);
        assert_eq!(d.data, data);
    }

    #[test]
    fn roundtrip_binary_with_newlines_and_invalid_utf8() {
        let m = meta("blob.bin", FileFormat::Binary);
        let data = [0xffu8, 0x00, b'\n', 0xfe, b'\n'];
        let d = decode(&encode(&m, &data));
        assert_eq!(d.data, data);
        assert_eq!(d.meta.format, FileFormat::Binary);
    }

    #[test]
    fn default_env_stays_raw() {
        let m = FileMeta::legacy_env();
        let data = b"A=1\nB=2\n";
        assert_eq!(encode(&m, data), data.to_vec()); // no container
    }

    #[test]
    fn named_env_gets_container() {
        let m = meta(".env.production", FileFormat::Env);
        let encoded = encode(&m, b"A=1\n");
        assert!(encoded.starts_with(MAGIC));
        let d = decode(&encoded);
        assert_eq!(d.meta.file_name, ".env.production");
        assert_eq!(d.meta.format, FileFormat::Env);
    }

    #[test]
    fn legacy_raw_payload_decodes_as_env() {
        let d = decode(b"A=1\nB=2\n");
        assert!(d.legacy);
        assert_eq!(d.meta, FileMeta::legacy_env());
        assert_eq!(d.data, b"A=1\nB=2\n");
    }

    #[test]
    fn env_that_starts_with_magic_but_no_meta_is_legacy() {
        let tricky = b"DMGF1\nNOT_JSON=oops\nA=1\n";
        let d = decode(tricky);
        assert!(d.legacy);
        assert_eq!(d.data, tricky.to_vec());
    }

    #[test]
    fn payload_containing_magic_mid_file_is_untouched() {
        let m = meta("notes.txt", FileFormat::Text);
        let data = b"before\nDMGF1\nafter";
        let d = decode(&encode(&m, data));
        assert_eq!(d.data, data);
    }

    /// Spec Appendix A.9 test vector — keep byte-for-byte in sync with spec.md.
    #[test]
    fn spec_a9_test_vector() {
        let m = meta("dataSources.xml", FileFormat::Text);
        let encoded = encode(&m, b"<x/>");
        assert_eq!(
            encoded,
            b"DMGF1\n{\"file_name\":\"dataSources.xml\",\"format\":\"text\"}\n<x/>".to_vec()
        );
    }
}
