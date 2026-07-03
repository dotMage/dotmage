//! Abstract storage backend trait matching the API contract (Appendix B).

use std::any::Any;

use crate::types::*;

/// Helper trait for downcasting trait objects.
pub trait AsAny {
    fn as_any(&self) -> &dyn Any;
}

impl<T: 'static> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Backend abstraction over dotMage storage.
/// FsBackend implements this for local testing; HttpBackend for real server.
pub trait Backend: AsAny {
    // --- Account ---
    fn account_exists(&self) -> Result<bool, BackendError>;
    fn account_init(&self, req: &AccountInitReq) -> Result<AccountInitResp, BackendError>;
    fn get_account_keys(&self) -> Result<AccountKeys, BackendError>;
    fn update_account_keys(&self, keys: &AccountKeys) -> Result<(), BackendError>;

    // --- Apps ---
    fn list_apps(&self) -> Result<Vec<AppInfo>, BackendError>;
    fn create_app(&self, name: &str) -> Result<(), BackendError>;
    fn delete_app(&self, name: &str) -> Result<(), BackendError>;

    // --- Environments ---
    fn list_envs(&self, app: &str) -> Result<Vec<EnvInfo>, BackendError>;
    fn create_env(&self, app: &str, env: &str, copy_from: Option<&str>)
        -> Result<(), BackendError>;
    fn delete_env(&self, app: &str, env: &str) -> Result<(), BackendError>;

    // --- Revisions ---
    fn push_revision(
        &self,
        app: &str,
        env: &str,
        blob: &str,
        parent_rev: u64,
    ) -> Result<RevisionMeta, BackendError>;

    fn pull_revision(&self, app: &str, env: &str, rev: &RevSpec) -> Result<Revision, BackendError>;

    fn list_revisions(&self, app: &str, env: &str) -> Result<Vec<RevisionMeta>, BackendError>;

    fn rollback(&self, app: &str, env: &str, to_rev: u64) -> Result<RevisionMeta, BackendError>;

    // --- AK rotation (spec L) ---
    fn rotate_begin(&self, req: &RotateBeginReq) -> Result<RotateStatus, BackendError>;
    fn rotate_status(&self) -> Result<RotateStatus, BackendError>;
    fn rotate_put_blob(
        &self,
        app: &str,
        env: &str,
        rev: u64,
        blob: &str,
        key_gen: u64,
    ) -> Result<(), BackendError>;
    fn rotate_complete(&self) -> Result<u64, BackendError>;
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("not initialized")]
    NotInitialized,
    #[error("{0}")]
    Other(String),
}
