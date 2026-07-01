//! Filesystem-based storage backend for local development/testing.
//!
//! Layout:
//! ```text
//! {root}/
//! ├── account.json
//! └── apps/
//!     └── {app}/
//!         └── envs/
//!             └── {env}/
//!                 ├── meta.json          # { latest_rev, updated_at }
//!                 └── revisions/
//!                     └── {rev}.json     # { blob, created_at, device_id, parent_rev, rollback_of }
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::backend::{Backend, BackendError};
use crate::types::*;

/// A backend that stores encrypted blobs on the local filesystem.
pub struct FsBackend {
    root: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct FsAccount {
    account_id: String,
    keys: AccountKeys,
    bootstrap_used: bool,
}

#[derive(Serialize, Deserialize)]
struct FsEnvMeta {
    latest_rev: u64,
    updated_at: String,
}

#[derive(Serialize, Deserialize)]
struct FsRevision {
    rev_number: u64,
    blob: String,
    content_hash: Option<String>,
    created_at: String,
    device_id: String,
    parent_rev: Option<u64>,
    rollback_of: Option<u64>,
}

impl FsBackend {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn account_path(&self) -> PathBuf {
        self.root.join("account.json")
    }

    fn app_dir(&self, app: &str) -> PathBuf {
        self.root.join("apps").join(app.replace('/', "%2F"))
    }

    fn env_dir(&self, app: &str, env: &str) -> PathBuf {
        self.app_dir(app).join("envs").join(env)
    }

    fn env_meta_path(&self, app: &str, env: &str) -> PathBuf {
        self.env_dir(app, env).join("meta.json")
    }

    fn revisions_dir(&self, app: &str, env: &str) -> PathBuf {
        self.env_dir(app, env).join("revisions")
    }

    fn revision_path(&self, app: &str, env: &str, rev: u64) -> PathBuf {
        self.revisions_dir(app, env).join(format!("{rev}.json"))
    }

    fn load_account(&self) -> Result<FsAccount, BackendError> {
        let path = self.account_path();
        if !path.exists() {
            return Err(BackendError::NotInitialized);
        }
        let data = fs::read_to_string(&path)?;
        serde_json::from_str(&data).map_err(|e| BackendError::Other(e.to_string()))
    }

    fn save_account(&self, account: &FsAccount) -> Result<(), BackendError> {
        fs::create_dir_all(&self.root)?;
        let data = serde_json::to_string_pretty(account)
            .map_err(|e| BackendError::Other(e.to_string()))?;
        fs::write(self.account_path(), data)?;
        Ok(())
    }

    fn load_env_meta(&self, app: &str, env: &str) -> Result<FsEnvMeta, BackendError> {
        let path = self.env_meta_path(app, env);
        if !path.exists() {
            return Err(BackendError::NotFound(format!("{app}/{env}")));
        }
        let data = fs::read_to_string(&path)?;
        serde_json::from_str(&data).map_err(|e| BackendError::Other(e.to_string()))
    }

    fn save_env_meta(&self, app: &str, env: &str, meta: &FsEnvMeta) -> Result<(), BackendError> {
        let dir = self.env_dir(app, env);
        fs::create_dir_all(&dir)?;
        let data =
            serde_json::to_string_pretty(meta).map_err(|e| BackendError::Other(e.to_string()))?;
        fs::write(self.env_meta_path(app, env), data)?;
        Ok(())
    }

    fn load_revision(&self, app: &str, env: &str, rev: u64) -> Result<FsRevision, BackendError> {
        let path = self.revision_path(app, env, rev);
        if !path.exists() {
            return Err(BackendError::NotFound(format!("{app}/{env}/rev {rev}")));
        }
        let data = fs::read_to_string(&path)?;
        serde_json::from_str(&data).map_err(|e| BackendError::Other(e.to_string()))
    }

    fn save_revision(&self, app: &str, env: &str, rev: &FsRevision) -> Result<(), BackendError> {
        let dir = self.revisions_dir(app, env);
        fs::create_dir_all(&dir)?;
        let data =
            serde_json::to_string_pretty(rev).map_err(|e| BackendError::Other(e.to_string()))?;
        fs::write(self.revision_path(app, env, rev.rev_number), data)?;
        Ok(())
    }

    fn now_iso() -> String {
        Utc::now().to_rfc3339()
    }

    fn list_subdirs(dir: &Path) -> Result<Vec<String>, BackendError> {
        if !dir.exists() {
            return Ok(vec![]);
        }
        let mut names = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    names.push(name.to_string());
                }
            }
        }
        names.sort();
        Ok(names)
    }
}

impl Backend for FsBackend {
    fn account_exists(&self) -> Result<bool, BackendError> {
        Ok(self.account_path().exists())
    }

    fn account_init(&self, req: &AccountInitReq) -> Result<AccountInitResp, BackendError> {
        if self.account_path().exists() {
            return Err(BackendError::AlreadyExists("account".into()));
        }

        let account_id = uuid_v4();
        let account = FsAccount {
            account_id: account_id.clone(),
            keys: AccountKeys {
                salt: req.salt.clone(),
                argon_params: req.argon_params.clone(),
                nonce_ak: req.nonce_ak.clone(),
                wrapped_ak: req.wrapped_ak.clone(),
                salt_rc: req.salt_rc.clone(),
                nonce_rc: req.nonce_rc.clone(),
                wrapped_ak_rc: req.wrapped_ak_rc.clone(),
            },
            bootstrap_used: true,
        };
        self.save_account(&account)?;

        Ok(AccountInitResp {
            account_id,
            device_token: format!("fs_tok_{}", &uuid_v4()[..8]),
            refresh_token: format!("fs_ref_{}", &uuid_v4()[..8]),
            expires_at: "2099-12-31T23:59:59Z".into(),
        })
    }

    fn get_account_keys(&self) -> Result<AccountKeys, BackendError> {
        let account = self.load_account()?;
        Ok(account.keys)
    }

    fn update_account_keys(&self, keys: &AccountKeys) -> Result<(), BackendError> {
        let mut account = self.load_account()?;
        account.keys = keys.clone();
        self.save_account(&account)
    }

    fn list_apps(&self) -> Result<Vec<AppInfo>, BackendError> {
        let apps_dir = self.root.join("apps");
        let dir_names = Self::list_subdirs(&apps_dir)?;
        let mut result = Vec::new();
        for dir_name in dir_names {
            // Decode %2F back to / for display (app_dir encodes / → %2F on disk)
            let app_name = dir_name.replace("%2F", "/");
            let envs = self.list_envs(&app_name)?;
            let updated_at = envs
                .iter()
                .map(|e| e.updated_at.as_str())
                .max()
                .unwrap_or("")
                .to_string();
            result.push(AppInfo {
                name: app_name,
                environments: envs.iter().map(|e| e.name.clone()).collect(),
                updated_at,
            });
        }
        Ok(result)
    }

    fn create_app(&self, name: &str) -> Result<(), BackendError> {
        let dir = self.app_dir(name);
        if dir.exists() {
            return Err(BackendError::AlreadyExists(format!("app '{name}'")));
        }
        fs::create_dir_all(dir.join("envs"))?;
        Ok(())
    }

    fn delete_app(&self, name: &str) -> Result<(), BackendError> {
        let dir = self.app_dir(name);
        if !dir.exists() {
            return Err(BackendError::NotFound(format!("app '{name}'")));
        }
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    fn list_envs(&self, app: &str) -> Result<Vec<EnvInfo>, BackendError> {
        let envs_dir = self.app_dir(app).join("envs");
        let names = Self::list_subdirs(&envs_dir)?;
        let mut result = Vec::new();
        for name in names {
            match self.load_env_meta(app, &name) {
                Ok(meta) => result.push(EnvInfo {
                    name,
                    latest_rev: meta.latest_rev,
                    updated_at: meta.updated_at,
                }),
                Err(_) => result.push(EnvInfo {
                    name,
                    latest_rev: 0,
                    updated_at: String::new(),
                }),
            }
        }
        Ok(result)
    }

    fn create_env(
        &self,
        app: &str,
        env: &str,
        copy_from: Option<&str>,
    ) -> Result<(), BackendError> {
        if !self.app_dir(app).exists() {
            return Err(BackendError::NotFound(format!("app '{app}'")));
        }
        let env_dir = self.env_dir(app, env);
        if env_dir.exists() {
            return Err(BackendError::AlreadyExists(format!("env '{app}/{env}'")));
        }

        fs::create_dir_all(self.revisions_dir(app, env))?;

        if let Some(src) = copy_from {
            // Copy latest revision from source env
            let src_meta = self.load_env_meta(app, src)?;
            if src_meta.latest_rev > 0 {
                let src_rev = self.load_revision(app, src, src_meta.latest_rev)?;
                let new_rev = FsRevision {
                    rev_number: 1,
                    blob: src_rev.blob,
                    content_hash: src_rev.content_hash,
                    created_at: Self::now_iso(),
                    device_id: "local".into(),
                    parent_rev: None,
                    rollback_of: None,
                };
                self.save_revision(app, env, &new_rev)?;
                self.save_env_meta(
                    app,
                    env,
                    &FsEnvMeta {
                        latest_rev: 1,
                        updated_at: Self::now_iso(),
                    },
                )?;
                return Ok(());
            }
        }

        self.save_env_meta(
            app,
            env,
            &FsEnvMeta {
                latest_rev: 0,
                updated_at: Self::now_iso(),
            },
        )?;
        Ok(())
    }

    fn delete_env(&self, app: &str, env: &str) -> Result<(), BackendError> {
        let dir = self.env_dir(app, env);
        if !dir.exists() {
            return Err(BackendError::NotFound(format!("env '{app}/{env}'")));
        }
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    fn push_revision(
        &self,
        app: &str,
        env: &str,
        blob: &str,
        parent_rev: u64,
    ) -> Result<RevisionMeta, BackendError> {
        let meta = self.load_env_meta(app, env)?;
        if meta.latest_rev != parent_rev {
            return Err(BackendError::Conflict(format!(
                "remote is ahead (server rev {}, your parent {parent_rev})",
                meta.latest_rev
            )));
        }

        let new_rev_number = meta.latest_rev + 1;
        let now = Self::now_iso();

        let rev = FsRevision {
            rev_number: new_rev_number,
            blob: blob.to_string(),
            content_hash: None, // kept locally per spec
            created_at: now.clone(),
            device_id: "local".into(),
            parent_rev: if parent_rev > 0 {
                Some(parent_rev)
            } else {
                None
            },
            rollback_of: None,
        };
        self.save_revision(app, env, &rev)?;
        self.save_env_meta(
            app,
            env,
            &FsEnvMeta {
                latest_rev: new_rev_number,
                updated_at: now.clone(),
            },
        )?;

        Ok(RevisionMeta {
            rev_number: new_rev_number,
            content_hash: None,
            created_at: now,
            device_id: "local".into(),
            rollback_of: None,
        })
    }

    fn pull_revision(&self, app: &str, env: &str, rev: &RevSpec) -> Result<Revision, BackendError> {
        let rev_number = match rev {
            RevSpec::Latest => {
                let meta = self.load_env_meta(app, env)?;
                if meta.latest_rev == 0 {
                    return Err(BackendError::NotFound(format!(
                        "no revisions in {app}/{env}"
                    )));
                }
                meta.latest_rev
            }
            RevSpec::Number(n) => *n,
        };

        let fs_rev = self.load_revision(app, env, rev_number)?;
        Ok(Revision {
            rev_number: fs_rev.rev_number,
            blob: fs_rev.blob,
            content_hash: fs_rev.content_hash,
            created_at: fs_rev.created_at,
            device_id: fs_rev.device_id,
            parent_rev: fs_rev.parent_rev,
            rollback_of: fs_rev.rollback_of,
        })
    }

    fn list_revisions(&self, app: &str, env: &str) -> Result<Vec<RevisionMeta>, BackendError> {
        let dir = self.revisions_dir(app, env);
        if !dir.exists() {
            return Ok(vec![]);
        }

        let mut revs = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".json") {
                let data = fs::read_to_string(entry.path())?;
                let rev: FsRevision =
                    serde_json::from_str(&data).map_err(|e| BackendError::Other(e.to_string()))?;
                revs.push(RevisionMeta {
                    rev_number: rev.rev_number,
                    content_hash: rev.content_hash,
                    created_at: rev.created_at,
                    device_id: rev.device_id,
                    rollback_of: rev.rollback_of,
                });
            }
        }
        revs.sort_by_key(|r| std::cmp::Reverse(r.rev_number));
        Ok(revs)
    }

    fn rollback(&self, app: &str, env: &str, to_rev: u64) -> Result<RevisionMeta, BackendError> {
        let source = self.load_revision(app, env, to_rev)?;
        let meta = self.load_env_meta(app, env)?;

        let new_rev_number = meta.latest_rev + 1;
        let now = Self::now_iso();

        let rev = FsRevision {
            rev_number: new_rev_number,
            blob: source.blob,
            content_hash: source.content_hash,
            created_at: now.clone(),
            device_id: "local".into(),
            parent_rev: Some(meta.latest_rev),
            rollback_of: Some(to_rev),
        };
        self.save_revision(app, env, &rev)?;
        self.save_env_meta(
            app,
            env,
            &FsEnvMeta {
                latest_rev: new_rev_number,
                updated_at: now.clone(),
            },
        )?;

        Ok(RevisionMeta {
            rev_number: new_rev_number,
            content_hash: rev.content_hash,
            created_at: now,
            device_id: "local".into(),
            rollback_of: Some(to_rev),
        })
    }
}

fn uuid_v4() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]),
        u16::from_be_bytes([bytes[8], bytes[9]]),
        u64::from_be_bytes([
            0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
        ])
    )
}
