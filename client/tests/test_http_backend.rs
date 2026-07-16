//! Integration test: HttpBackend against a real dotMage server.
//!
//! This test starts a Python uvicorn server as a subprocess and runs
//! the full push/pull cycle through HttpBackend.
//!
//! Requires: server virtualenv at ../../server/.venv
//! Skip with: cargo test --test test_http_backend -- --ignored

use dotmage_client::backend::Backend;
use dotmage_client::backend_http::HttpBackend;
use dotmage_client::types::*;
use dotmage_crypto::{blob, envelope, kdf, secret};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use std::process::{Child, Command};

const SERVER_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../server");
const BOOTSTRAP_SECRET: &str = "test-integration-secret";

struct ServerGuard {
    child: Child,
    port: u16,
}

impl ServerGuard {
    fn start() -> Self {
        let port = 18321_u16;
        let venv_python = format!("{SERVER_DIR}/.venv/bin/python");

        let child = Command::new(&venv_python)
            .args([
                "-m",
                "uvicorn",
                "app.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
            ])
            .current_dir(SERVER_DIR)
            .env("DOTMAGE_DB_URL", "sqlite:///test_integration.db")
            .env("DOTMAGE_BOOTSTRAP_SECRET", BOOTSTRAP_SECRET)
            .env("DOTMAGE_TOKEN_TTL", "1h")
            .env("DOTMAGE_REFRESH_TTL", "7d")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("Failed to start server (is server/.venv set up?)");

        let guard = Self { child, port };

        // Wait for server to be ready
        let base = format!("http://127.0.0.1:{port}");
        for _ in 0..50 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if reqwest::blocking::get(format!("{base}/health")).is_ok() {
                return guard;
            }
        }
        drop(guard);
        panic!("Server did not start within 5 seconds");
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Clean up test DB
        let db_path = format!("{SERVER_DIR}/test_integration.db");
        let _ = std::fs::remove_file(&db_path);
    }
}

#[test]
#[ignore] // Run explicitly: cargo test --test test_http_backend -- --ignored
fn full_cycle_against_real_server() {
    let server = ServerGuard::start();
    let base_url = server.base_url();

    // 1. Bootstrap account
    let password = b"integration-test-password";
    let salt = kdf::generate_salt();
    let mk = kdf::derive_master_key(password, &salt).unwrap();
    let ak = envelope::generate_account_key();
    let wrapped = envelope::wrap_ak(&mk, &ak).unwrap();

    let req = AccountInitReq {
        salt: B64.encode(salt),
        argon_params: ArgonParamsDto {
            memory: kdf::ARGON2_MEMORY_KIB,
            iterations: kdf::ARGON2_ITERATIONS,
            parallelism: kdf::ARGON2_PARALLELISM,
            version: kdf::ARGON2_VERSION,
        },
        nonce_ak: B64.encode(wrapped.nonce),
        wrapped_ak: B64.encode(&wrapped.ciphertext),
        device_name: "test-machine".into(),
        bootstrap_secret: BOOTSTRAP_SECRET.into(),
        salt_rc: None,
        nonce_rc: None,
        wrapped_ak_rc: None,
    };

    // Use a temporary backend with no token for init
    let init_backend = HttpBackend::new(&base_url, "");
    let resp = init_backend.account_init(&req).unwrap();
    assert!(!resp.device_token.is_empty());

    // 2. Create authenticated backend
    let backend = HttpBackend::new(&base_url, &resp.device_token);

    // 3. Verify account exists
    assert!(backend.account_exists().unwrap());

    // 4. Get keys back
    let keys = backend.get_account_keys().unwrap();
    assert_eq!(keys.salt, B64.encode(salt));

    // 5. Create app + env
    backend.create_app("integration-app").unwrap();
    backend.create_env("integration-app", "dev").unwrap();

    // 6. Push
    let plaintext = b"DATABASE_URL=postgres://test\nAPI_KEY=secret123\n";
    let encrypted = secret::encrypt_secret(&ak, plaintext, "integration-app", "dev", 1).unwrap();
    let blob_str = blob::encode_blob(&encrypted);

    let push_meta = backend
        .push_revision("integration-app", "dev", &blob_str, 0)
        .unwrap();
    assert_eq!(push_meta.rev_number, 1);

    // 7. Pull and decrypt
    let rev = backend
        .pull_revision("integration-app", "dev", &RevSpec::Latest)
        .unwrap();
    assert_eq!(rev.rev_number, 1);

    let decoded = blob::decode_blob(&rev.blob).unwrap();
    let decrypted = secret::decrypt_secret(&ak, &decoded, "integration-app", "dev", 1).unwrap();
    assert_eq!(decrypted, plaintext);

    // 8. Push rev 2
    let plaintext2 = b"DATABASE_URL=postgres://prod\nAPI_KEY=newkey\n";
    let encrypted2 = secret::encrypt_secret(&ak, plaintext2, "integration-app", "dev", 2).unwrap();
    backend
        .push_revision("integration-app", "dev", &blob::encode_blob(&encrypted2), 1)
        .unwrap();

    // 9. History
    let history = backend.list_revisions("integration-app", "dev").unwrap();
    assert_eq!(history.len(), 2);

    // 10. Conflict detection
    let encrypted3 = secret::encrypt_secret(&ak, b"STALE", "integration-app", "dev", 3).unwrap();
    let conflict = backend.push_revision(
        "integration-app",
        "dev",
        &blob::encode_blob(&encrypted3),
        1, // stale parent
    );
    assert!(conflict.is_err());

    // 11. Rollback
    let rb = backend.rollback("integration-app", "dev", 1).unwrap();
    assert_eq!(rb.rev_number, 3);
    assert_eq!(rb.rollback_of, Some(1));

    // 12. Apps list
    let apps = backend.list_apps().unwrap();
    assert_eq!(apps.len(), 1);
    assert_eq!(apps[0].name, "integration-app");

    println!("Full CLI↔Server integration test passed!");
}
