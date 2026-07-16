//! Integration tests: full cycle against FsBackend.
//! Phase 2 gate — these must all pass.

use dotmage_client::backend::Backend;
use dotmage_client::backend_fs::FsBackend;
use dotmage_client::types::*;
use dotmage_crypto::{blob, envelope, kdf, secret};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use tempfile::TempDir;

fn setup() -> (TempDir, FsBackend, [u8; 32]) {
    let tmp = TempDir::new().unwrap();
    let backend = FsBackend::new(tmp.path().to_path_buf());

    // Bootstrap account
    let password = b"test-password";
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
        device_name: "test".into(),
        bootstrap_secret: String::new(),
        salt_rc: None,
        nonce_rc: None,
        wrapped_ak_rc: None,
    };

    backend.account_init(&req).unwrap();
    (tmp, backend, *ak)
}

#[test]
fn full_cycle_init_push_pull() {
    let (_tmp, backend, ak) = setup();

    // Create app + env
    backend.create_app("myapp").unwrap();
    backend.create_env("myapp", "dev").unwrap();

    // Push revision 1
    let plaintext = b"DATABASE_URL=postgres://localhost\nSECRET=hunter2\n";
    let encrypted = secret::encrypt_secret(&ak, plaintext, "myapp", "dev", 1).unwrap();
    let blob_str = blob::encode_blob(&encrypted);
    let meta = backend.push_revision("myapp", "dev", &blob_str, 0).unwrap();
    assert_eq!(meta.rev_number, 1);

    // Pull revision 1
    let rev = backend
        .pull_revision("myapp", "dev", &RevSpec::Latest)
        .unwrap();
    assert_eq!(rev.rev_number, 1);
    let decoded = blob::decode_blob(&rev.blob).unwrap();
    let decrypted = secret::decrypt_secret(&ak, &decoded, "myapp", "dev", 1).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn multiple_revisions_and_history() {
    let (_tmp, backend, ak) = setup();

    backend.create_app("app2").unwrap();
    backend.create_env("app2", "dev").unwrap();

    // Push 3 revisions
    for i in 1..=3 {
        let data = format!("KEY=value{i}\n");
        let encrypted = secret::encrypt_secret(&ak, data.as_bytes(), "app2", "dev", i).unwrap();
        let blob_str = blob::encode_blob(&encrypted);
        backend
            .push_revision("app2", "dev", &blob_str, i - 1)
            .unwrap();
    }

    // History should show 3 revisions (newest first)
    let history = backend.list_revisions("app2", "dev").unwrap();
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].rev_number, 3);
    assert_eq!(history[2].rev_number, 1);

    // Pull specific revision
    let rev2 = backend
        .pull_revision("app2", "dev", &RevSpec::Number(2))
        .unwrap();
    let decoded = blob::decode_blob(&rev2.blob).unwrap();
    let decrypted = secret::decrypt_secret(&ak, &decoded, "app2", "dev", 2).unwrap();
    assert_eq!(String::from_utf8(decrypted).unwrap(), "KEY=value2\n");
}

#[test]
fn push_conflict_detection() {
    let (_tmp, backend, ak) = setup();

    backend.create_app("conflict").unwrap();
    backend.create_env("conflict", "dev").unwrap();

    // Push rev 1
    let encrypted = secret::encrypt_secret(&ak, b"V=1", "conflict", "dev", 1).unwrap();
    backend
        .push_revision("conflict", "dev", &blob::encode_blob(&encrypted), 0)
        .unwrap();

    // Try to push with stale parent_rev=0 → conflict
    let encrypted2 = secret::encrypt_secret(&ak, b"V=2", "conflict", "dev", 2).unwrap();
    let result = backend.push_revision("conflict", "dev", &blob::encode_blob(&encrypted2), 0);
    assert!(result.is_err());
}

#[test]
fn rollback_creates_new_revision() {
    let (_tmp, backend, ak) = setup();

    backend.create_app("rollback").unwrap();
    backend.create_env("rollback", "dev").unwrap();

    // Push 2 revisions
    for i in 1..=2 {
        let data = format!("V={i}\n");
        let encrypted = secret::encrypt_secret(&ak, data.as_bytes(), "rollback", "dev", i).unwrap();
        backend
            .push_revision("rollback", "dev", &blob::encode_blob(&encrypted), i - 1)
            .unwrap();
    }

    // Rollback to rev 1
    let meta = backend.rollback("rollback", "dev", 1).unwrap();
    assert_eq!(meta.rev_number, 3);
    assert_eq!(meta.rollback_of, Some(1));

    // Rev 3 should have same blob as rev 1
    let rev3 = backend
        .pull_revision("rollback", "dev", &RevSpec::Number(3))
        .unwrap();
    let rev1 = backend
        .pull_revision("rollback", "dev", &RevSpec::Number(1))
        .unwrap();
    assert_eq!(rev3.blob, rev1.blob);
}

#[test]
fn environments_independent_chains() {
    let (_tmp, backend, ak) = setup();

    backend.create_app("envtest").unwrap();
    backend.create_env("envtest", "dev").unwrap();
    backend.create_env("envtest", "prod").unwrap();

    // Push to dev
    let enc_dev = secret::encrypt_secret(&ak, b"ENV=dev\n", "envtest", "dev", 1).unwrap();
    backend
        .push_revision("envtest", "dev", &blob::encode_blob(&enc_dev), 0)
        .unwrap();

    // Push to prod
    let enc_prod = secret::encrypt_secret(&ak, b"ENV=prod\n", "envtest", "prod", 1).unwrap();
    backend
        .push_revision("envtest", "prod", &blob::encode_blob(&enc_prod), 0)
        .unwrap();

    // Dev and prod have independent rev chains
    let envs = backend.list_envs("envtest").unwrap();
    assert_eq!(envs.len(), 2);
    for env in &envs {
        assert_eq!(env.latest_rev, 1);
    }

    // Cross-env AAD check: prod blob can't be decrypted with dev AAD
    let prod_rev = backend
        .pull_revision("envtest", "prod", &RevSpec::Latest)
        .unwrap();
    let prod_decoded = blob::decode_blob(&prod_rev.blob).unwrap();
    let cross_result = secret::decrypt_secret(&ak, &prod_decoded, "envtest", "dev", 1);
    assert!(
        cross_result.is_err(),
        "cross-env decryption should fail due to AAD"
    );
}

#[test]
fn account_keys_roundtrip() {
    let (_tmp, backend, _ak) = setup();

    let keys = backend.get_account_keys().unwrap();
    assert!(!keys.salt.is_empty());
    assert_eq!(keys.argon_params.memory, kdf::ARGON2_MEMORY_KIB);

    // Derive MK from password and unwrap AK to verify
    let salt_bytes: [u8; 16] = B64.decode(&keys.salt).unwrap().try_into().unwrap();
    let params = kdf::ArgonParams {
        memory: keys.argon_params.memory,
        iterations: keys.argon_params.iterations,
        parallelism: keys.argon_params.parallelism,
        version: keys.argon_params.version,
    };
    let mk = kdf::derive_master_key_with_params(b"test-password", &salt_bytes, &params).unwrap();
    let nonce: [u8; 24] = B64.decode(&keys.nonce_ak).unwrap().try_into().unwrap();
    let ct = B64.decode(&keys.wrapped_ak).unwrap();
    let wrapped = envelope::WrappedAk {
        nonce,
        ciphertext: ct,
    };
    let unwrapped = envelope::unwrap_ak(&mk, &wrapped).unwrap();
    // AK should be 32 non-zero bytes
    assert_ne!(*unwrapped, [0u8; 32]);
}

#[test]
fn app_list_and_env_copy() {
    let (_tmp, backend, ak) = setup();

    backend.create_app("copytest").unwrap();
    backend.create_env("copytest", "dev").unwrap();

    // Push to dev
    let enc = secret::encrypt_secret(&ak, b"DATA=hello\n", "copytest", "dev", 1).unwrap();
    backend
        .push_revision("copytest", "dev", &blob::encode_blob(&enc), 0)
        .unwrap();

    // Copy dev → staging the way the CLI does it: decrypt the source and
    // re-encrypt bound to the new env. A server-side byte-copy cannot work —
    // AEAD ties the blob to app|env|rev.
    let src = backend
        .pull_revision("copytest", "dev", &RevSpec::Latest)
        .unwrap();
    let plain = secret::decrypt_secret(
        &ak,
        &blob::decode_blob(&src.blob).unwrap(),
        "copytest",
        "dev",
        src.rev_number,
    )
    .unwrap();
    backend.create_env("copytest", "staging").unwrap();
    let enc2 = secret::encrypt_secret(&ak, &plain, "copytest", "staging", 1).unwrap();
    backend
        .push_revision("copytest", "staging", &blob::encode_blob(&enc2), 0)
        .unwrap();

    let envs = backend.list_envs("copytest").unwrap();
    assert_eq!(envs.len(), 2);
    let staging = envs.iter().find(|e| e.name == "staging").unwrap();
    assert_eq!(staging.latest_rev, 1); // copied rev

    // The copied revision must decrypt under the NEW env's AAD.
    let copied = backend
        .pull_revision("copytest", "staging", &RevSpec::Latest)
        .unwrap();
    let plain2 = secret::decrypt_secret(
        &ak,
        &blob::decode_blob(&copied.blob).unwrap(),
        "copytest",
        "staging",
        1,
    )
    .unwrap();
    assert_eq!(plain2, b"DATA=hello\n");

    // Apps list
    let apps = backend.list_apps().unwrap();
    assert_eq!(apps.len(), 1);
    assert_eq!(apps[0].name, "copytest");
    assert!(apps[0].environments.contains(&"dev".to_string()));
    assert!(apps[0].environments.contains(&"staging".to_string()));
}

#[test]
fn duplicate_app_and_env_errors() {
    let (_tmp, backend, _ak) = setup();

    backend.create_app("dup").unwrap();
    assert!(backend.create_app("dup").is_err()); // already exists

    backend.create_env("dup", "dev").unwrap();
    assert!(backend.create_env("dup", "dev").is_err()); // already exists
}

#[test]
fn delete_env() {
    let (_tmp, backend, _ak) = setup();

    backend.create_app("deltest").unwrap();
    backend.create_env("deltest", "dev").unwrap();
    backend.create_env("deltest", "staging").unwrap();

    assert_eq!(backend.list_envs("deltest").unwrap().len(), 2);

    backend.delete_env("deltest", "staging").unwrap();
    assert_eq!(backend.list_envs("deltest").unwrap().len(), 1);
}

#[test]
fn account_init_once_only() {
    let (_tmp, backend, _ak) = setup();

    let req = AccountInitReq {
        salt: B64.encode([0u8; 16]),
        argon_params: ArgonParamsDto {
            memory: 65536,
            iterations: 3,
            parallelism: 1,
            version: 19,
        },
        nonce_ak: B64.encode([0u8; 24]),
        wrapped_ak: B64.encode([0u8; 48]),
        device_name: "second".into(),
        bootstrap_secret: String::new(),
        salt_rc: None,
        nonce_rc: None,
        wrapped_ak_rc: None,
    };
    assert!(backend.account_init(&req).is_err()); // solo mode — one account
}
