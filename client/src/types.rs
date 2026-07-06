//! Shared data types matching the API contract (Appendix B).

use serde::{Deserialize, Serialize};

/// Account cryptographic keys (B.2, B.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountKeys {
    pub salt: String,
    pub argon_params: ArgonParamsDto,
    pub nonce_ak: String,
    pub wrapped_ak: String,
    // Recovery (Appendix J)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt_rc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_rc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapped_ak_rc: Option<String>,
    /// AK generation this wrap unwraps (spec L; pre-rotation servers omit it).
    #[serde(default = "default_key_gen")]
    pub key_gen: u64,
}

pub fn default_key_gen() -> u64 {
    1
}

/// Argon2 parameters DTO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgonParamsDto {
    pub memory: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub version: u32,
}

/// Account init request (B.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInitReq {
    pub salt: String,
    pub argon_params: ArgonParamsDto,
    pub nonce_ak: String,
    pub wrapped_ak: String,
    pub device_name: String,
    pub bootstrap_secret: String,
    // Recovery
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt_rc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_rc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapped_ak_rc: Option<String>,
}

/// Account init response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInitResp {
    #[serde(alias = "device_id")]
    pub account_id: String,
    pub device_token: String,
    pub refresh_token: String,
    #[serde(alias = "token_expires_at")]
    pub expires_at: String,
}

/// App info (B.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInfo {
    pub name: String,
    pub environments: Vec<String>,
    pub updated_at: String,
}

/// Environment info (B.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvInfo {
    pub name: String,
    pub latest_rev: u64,
    pub updated_at: String,
}

/// Revision metadata (for history listings — no blob).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevisionMeta {
    pub rev_number: u64,
    pub content_hash: Option<String>,
    pub created_at: String,
    pub device_id: String,
    pub rollback_of: Option<u64>,
}

/// Full revision with blob (for pull).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revision {
    pub rev_number: u64,
    pub blob: String,
    pub content_hash: Option<String>,
    pub created_at: String,
    pub device_id: String,
    pub parent_rev: Option<u64>,
    pub rollback_of: Option<u64>,
    /// AK generation the blob is encrypted with (spec L).
    #[serde(default = "default_key_gen")]
    pub key_gen: u64,
}

/// One stale revision to re-encrypt during rotation (spec L.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaleRevision {
    pub app: String,
    pub env: String,
    pub rev_number: u64,
}

/// Rotation status (GET /account/rotate).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateStatus {
    pub in_progress: bool,
    pub current_key_gen: u64,
    #[serde(default)]
    pub new_key_gen: Option<u64>,
    #[serde(default)]
    pub stale_count: u64,
    #[serde(default)]
    pub stale: Vec<StaleRevision>,
    #[serde(default)]
    pub pending_nonce_ak: Option<String>,
    #[serde(default)]
    pub pending_wrapped_ak: Option<String>,
}

/// Body of POST /account/rotate/begin (spec L.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateBeginReq {
    pub new_key_gen: u64,
    pub nonce_ak: String,
    pub wrapped_ak: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt_rc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_rc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapped_ak_rc: Option<String>,
}

/// Which revision to pull.
#[derive(Debug, Clone)]
pub enum RevSpec {
    Latest,
    Number(u64),
}

/// Health info (B.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthInfo {
    pub status: String,
    pub version: String,
    pub account_exists: bool,
    /// Optional capabilities (B.9): "rotation", "team". Old servers omit it.
    #[serde(default)]
    pub features: Vec<String>,
    /// Display name the server advertises (B.9); clients adopt it as the
    /// default server name. Absent on servers without DOTMAGE_SERVER_NAME.
    #[serde(default)]
    pub server_name: Option<String>,
}

/// Identity of the calling device/user (B.9).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoamiInfo {
    pub user_id: Option<String>,
    pub name: String,
    pub role: String,
    pub device_id: String,
    pub device_name: String,
}

/// Team member entry (GET /users).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub name: String,
    pub role: String,
    pub status: String,
    pub key_gen: u64,
    pub created_at: String,
}

/// Pending invitation entry (GET /users).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitationInfo {
    pub id: String,
    pub name: String,
    pub role: String,
    pub status: String,
    pub expires_at: String,
}

/// Step-1 redemption response (K.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedeemResp {
    pub sealed_ak: String,
    pub nonce_inv: String,
    #[serde(default = "default_key_gen")]
    pub key_gen: u64,
    pub name: String,
    pub role: String,
    pub argon_defaults: ArgonParamsDto,
}
