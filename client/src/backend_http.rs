//! HTTP-based storage backend — talks to dotMage server API.

use std::cell::RefCell;

use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde::Deserialize;

use crate::backend::{Backend, BackendError};
use crate::keychain;
use crate::token::{self, ServerTokens};
use crate::types::*;

/// A backend that communicates with the dotMage server over HTTP.
/// Uses RefCell for interior mutability so token refresh works through `&self`.
pub struct HttpBackend {
    base_url: String,
    client: Client,
    token: RefCell<String>,
    refresh_token: RefCell<String>,
    server_hash: String,
}

#[derive(Deserialize)]
struct ErrorBody {
    error: Option<ErrorDetail>,
}

#[derive(Deserialize)]
struct ErrorDetail {
    message: Option<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct RefreshResp {
    device_token: String,
    refresh_token: String,
    device_id: String,
    token_expires_at: String,
}

#[derive(Deserialize)]
pub struct DeviceAuthResp {
    pub device_token: String,
    pub refresh_token: String,
    pub device_id: String,
    #[allow(dead_code)]
    pub token_expires_at: String,
}

/// Encode a value for use in a URL path segment (escapes `/` etc.)
fn encode_path(s: &str) -> String {
    s.replace('%', "%25").replace('/', "%2F")
}

impl HttpBackend {
    pub fn new(base_url: &str, device_token: &str) -> Self {
        let server_hash = keychain::server_hash(base_url);
        let refresh = token::load_tokens(&server_hash)
            .ok()
            .flatten()
            .map(|t| t.refresh_token)
            .unwrap_or_default();

        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: Client::new(),
            token: RefCell::new(device_token.to_string()),
            refresh_token: RefCell::new(refresh),
            server_hash,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api/v1{}", self.base_url, path)
    }

    fn auth_header(&self) -> (String, String) {
        (
            "Authorization".to_string(),
            format!("Bearer {}", self.token.borrow()),
        )
    }

    /// Make an authenticated GET request with auto-refresh on 401.
    fn auth_get(&self, path: &str) -> Result<(StatusCode, String), BackendError> {
        let (hdr, val) = self.auth_header();
        let resp = self
            .client
            .get(self.url(path))
            .header(&hdr, &val)
            .send()
            .map_err(|e| BackendError::Other(e.to_string()))?;

        if resp.status() == StatusCode::UNAUTHORIZED && self.try_refresh()? {
            let (hdr2, val2) = self.auth_header();
            let resp2 = self
                .client
                .get(self.url(path))
                .header(&hdr2, &val2)
                .send()
                .map_err(|e| BackendError::Other(e.to_string()))?;
            let status = resp2.status();
            let body = resp2
                .text()
                .map_err(|e| BackendError::Other(e.to_string()))?;
            return Ok((status, body));
        }

        let status = resp.status();
        let body = resp
            .text()
            .map_err(|e| BackendError::Other(e.to_string()))?;
        Ok((status, body))
    }

    /// Make an authenticated POST request with auto-refresh on 401.
    fn auth_post_json(
        &self,
        path: &str,
        json: &serde_json::Value,
    ) -> Result<(StatusCode, String), BackendError> {
        let (hdr, val) = self.auth_header();
        let resp = self
            .client
            .post(self.url(path))
            .header(&hdr, &val)
            .json(json)
            .send()
            .map_err(|e| BackendError::Other(e.to_string()))?;

        if resp.status() == StatusCode::UNAUTHORIZED && self.try_refresh()? {
            let (hdr2, val2) = self.auth_header();
            let resp2 = self
                .client
                .post(self.url(path))
                .header(&hdr2, &val2)
                .json(json)
                .send()
                .map_err(|e| BackendError::Other(e.to_string()))?;
            let status = resp2.status();
            let body = resp2
                .text()
                .map_err(|e| BackendError::Other(e.to_string()))?;
            return Ok((status, body));
        }

        let status = resp.status();
        let body = resp
            .text()
            .map_err(|e| BackendError::Other(e.to_string()))?;
        Ok((status, body))
    }

    /// Try to refresh the device token. Returns true if successful.
    fn try_refresh(&self) -> Result<bool, BackendError> {
        let refresh = self.refresh_token.borrow().clone();
        if refresh.is_empty() {
            return Ok(false);
        }

        let resp = self
            .client
            .post(self.url("/auth/refresh"))
            .json(&serde_json::json!({"refresh_token": refresh}))
            .send()
            .map_err(|e| BackendError::Other(e.to_string()))?;

        if !resp.status().is_success() {
            return Ok(false);
        }

        let data: RefreshResp = resp
            .json()
            .map_err(|e| BackendError::Other(e.to_string()))?;

        // Update in-memory tokens
        *self.token.borrow_mut() = data.device_token.clone();
        *self.refresh_token.borrow_mut() = data.refresh_token.clone();

        // Persist to disk
        let _ = token::save_tokens(
            &self.server_hash,
            &ServerTokens {
                device_token: data.device_token,
                refresh_token: data.refresh_token,
                device_id: data.device_id,
            },
        );

        Ok(true)
    }

    fn extract_error(status: StatusCode, body: &str) -> BackendError {
        if let Ok(err) = serde_json::from_str::<ErrorBody>(body) {
            if let Some(detail) = err.error {
                let msg = detail.message.unwrap_or_else(|| status.to_string());
                return match status {
                    StatusCode::NOT_FOUND => BackendError::NotFound(msg),
                    StatusCode::CONFLICT => BackendError::Conflict(msg),
                    _ => BackendError::Other(msg),
                };
            }
        }
        BackendError::Other(format!("HTTP {status}: {body}"))
    }

    // --- Methods outside Backend trait (device management) ---

    /// Generate an enrollment token for adding a new device.
    pub fn gen_enroll_token(
        &self,
        name: &str,
        ttl: &str,
    ) -> Result<(String, String), BackendError> {
        let (status, body) = self.auth_post_json(
            "/devices/enroll-token",
            &serde_json::json!({"name": name, "ttl": ttl, "kind": "enrollment"}),
        )?;

        if !status.is_success() {
            return Err(Self::extract_error(status, &body));
        }

        #[derive(Deserialize)]
        struct Resp {
            token: String,
            expires_at: String,
        }
        let parsed: Resp =
            serde_json::from_str(&body).map_err(|e| BackendError::Other(e.to_string()))?;
        Ok((parsed.token, parsed.expires_at))
    }

    /// Register a device using an enrollment token.
    pub fn register_with_enroll_token(
        &self,
        enroll_token: &str,
        device_name: &str,
    ) -> Result<DeviceAuthResp, BackendError> {
        let resp = self
            .client
            .post(self.url("/auth/device"))
            .header("Authorization", format!("Bearer {enroll_token}"))
            .json(&serde_json::json!({"device_name": device_name}))
            .send()
            .map_err(|e| BackendError::Other(e.to_string()))?;

        let status = resp.status();
        let body = resp
            .text()
            .map_err(|e| BackendError::Other(e.to_string()))?;
        if !status.is_success() {
            return Err(Self::extract_error(status, &body));
        }
        serde_json::from_str(&body).map_err(|e| BackendError::Other(e.to_string()))
    }

    /// Create a scoped CI token for a specific app+env.
    pub fn create_ci_token(
        &self,
        app: &str,
        env: &str,
        ttl: &str,
    ) -> Result<DeviceAuthResp, BackendError> {
        let (status, body) = self.auth_post_json(
            "/devices/ci-token",
            &serde_json::json!({"app": app, "env": env, "ttl": ttl}),
        )?;

        if !status.is_success() {
            return Err(Self::extract_error(status, &body));
        }
        serde_json::from_str(&body).map_err(|e| BackendError::Other(e.to_string()))
    }

    /// Register a device using the bootstrap secret.
    pub fn register_with_bootstrap(
        &self,
        bootstrap_secret: &str,
        device_name: &str,
    ) -> Result<DeviceAuthResp, BackendError> {
        let resp = self
            .client
            .post(self.url("/auth/device-register"))
            .json(&serde_json::json!({
                "bootstrap_secret": bootstrap_secret,
                "device_name": device_name,
            }))
            .send()
            .map_err(|e| BackendError::Other(e.to_string()))?;

        let status = resp.status();
        let body = resp
            .text()
            .map_err(|e| BackendError::Other(e.to_string()))?;
        if !status.is_success() {
            return Err(Self::extract_error(status, &body));
        }
        serde_json::from_str(&body).map_err(|e| BackendError::Other(e.to_string()))
    }
}

impl Backend for HttpBackend {
    fn account_exists(&self) -> Result<bool, BackendError> {
        let resp = self
            .client
            .get(format!("{}/health", self.base_url))
            .send()
            .map_err(|e| BackendError::Other(e.to_string()))?;
        let data: HealthInfo = resp
            .json()
            .map_err(|e| BackendError::Other(e.to_string()))?;
        Ok(data.account_exists)
    }

    fn account_init(&self, req: &AccountInitReq) -> Result<AccountInitResp, BackendError> {
        let body = serde_json::json!({
            "salt": req.salt,
            "argon_memory": req.argon_params.memory,
            "argon_iterations": req.argon_params.iterations,
            "argon_parallelism": req.argon_params.parallelism,
            "argon_version": req.argon_params.version,
            "nonce_ak": req.nonce_ak,
            "wrapped_ak": req.wrapped_ak,
            "device_name": req.device_name,
            "bootstrap_secret": req.bootstrap_secret,
            "salt_rc": req.salt_rc,
            "nonce_rc": req.nonce_rc,
            "wrapped_ak_rc": req.wrapped_ak_rc,
        });
        let resp = self
            .client
            .post(self.url("/account/init"))
            .json(&body)
            .send()
            .map_err(|e| BackendError::Other(e.to_string()))?;

        let status = resp.status();
        let body = resp
            .text()
            .map_err(|e| BackendError::Other(e.to_string()))?;
        if !status.is_success() {
            return Err(Self::extract_error(status, &body));
        }
        serde_json::from_str(&body).map_err(|e| BackendError::Other(e.to_string()))
    }

    fn get_account_keys(&self) -> Result<AccountKeys, BackendError> {
        let (status, body) = self.auth_get("/account/keys")?;
        if status == StatusCode::NOT_FOUND {
            return Err(BackendError::NotInitialized);
        }
        if !status.is_success() {
            return Err(Self::extract_error(status, &body));
        }

        #[derive(Deserialize)]
        struct FlatKeys {
            salt: String,
            argon_memory: u32,
            argon_iterations: u32,
            argon_parallelism: u32,
            argon_version: u32,
            nonce_ak: String,
            wrapped_ak: String,
            salt_rc: Option<String>,
            nonce_rc: Option<String>,
            wrapped_ak_rc: Option<String>,
            #[serde(default = "crate::types::default_key_gen")]
            key_gen: u64,
        }

        let flat: FlatKeys =
            serde_json::from_str(&body).map_err(|e| BackendError::Other(e.to_string()))?;
        Ok(AccountKeys {
            salt: flat.salt,
            argon_params: ArgonParamsDto {
                memory: flat.argon_memory,
                iterations: flat.argon_iterations,
                parallelism: flat.argon_parallelism,
                version: flat.argon_version,
            },
            nonce_ak: flat.nonce_ak,
            wrapped_ak: flat.wrapped_ak,
            salt_rc: flat.salt_rc,
            nonce_rc: flat.nonce_rc,
            wrapped_ak_rc: flat.wrapped_ak_rc,
            key_gen: flat.key_gen,
        })
    }

    fn update_account_keys(&self, keys: &AccountKeys) -> Result<(), BackendError> {
        let (hdr, val) = self.auth_header();
        let resp = self
            .client
            .patch(self.url("/account/keys"))
            .header(&hdr, &val)
            .json(keys)
            .send()
            .map_err(|e| BackendError::Other(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp
                .text()
                .map_err(|e| BackendError::Other(e.to_string()))?;
            return Err(Self::extract_error(status, &body));
        }
        Ok(())
    }

    fn list_apps(&self) -> Result<Vec<AppInfo>, BackendError> {
        let (status, body) = self.auth_get("/apps")?;
        if !status.is_success() {
            return Err(Self::extract_error(status, &body));
        }

        #[derive(Deserialize)]
        struct AppsResp {
            apps: Vec<AppRaw>,
        }
        #[derive(Deserialize)]
        struct AppRaw {
            name: String,
            environments: Option<Vec<EnvRaw>>,
            updated_at: Option<String>,
        }
        #[derive(Deserialize)]
        struct EnvRaw {
            name: String,
        }

        let parsed: AppsResp =
            serde_json::from_str(&body).map_err(|e| BackendError::Other(e.to_string()))?;
        Ok(parsed
            .apps
            .into_iter()
            .map(|a| AppInfo {
                name: a.name,
                environments: a
                    .environments
                    .unwrap_or_default()
                    .into_iter()
                    .map(|e| e.name)
                    .collect(),
                updated_at: a.updated_at.unwrap_or_default(),
            })
            .collect())
    }

    fn create_app(&self, name: &str) -> Result<(), BackendError> {
        let (status, body) = self.auth_post_json("/apps", &serde_json::json!({"name": name}))?;
        if !status.is_success() {
            return Err(Self::extract_error(status, &body));
        }
        Ok(())
    }

    fn list_envs(&self, app: &str) -> Result<Vec<EnvInfo>, BackendError> {
        let (status, body) = self.auth_get(&format!("/apps/{}/envs", encode_path(app)))?;
        if !status.is_success() {
            return Err(Self::extract_error(status, &body));
        }

        #[derive(Deserialize)]
        struct Resp {
            environments: Vec<EnvRaw>,
        }
        #[derive(Deserialize)]
        struct EnvRaw {
            name: String,
            latest_rev: u64,
            updated_at: Option<String>,
        }

        let parsed: Resp =
            serde_json::from_str(&body).map_err(|e| BackendError::Other(e.to_string()))?;
        Ok(parsed
            .environments
            .into_iter()
            .map(|e| EnvInfo {
                name: e.name,
                latest_rev: e.latest_rev,
                updated_at: e.updated_at.unwrap_or_default(),
            })
            .collect())
    }

    fn create_env(
        &self,
        app: &str,
        env: &str,
        copy_from: Option<&str>,
    ) -> Result<(), BackendError> {
        let mut body = serde_json::json!({"name": env});
        if let Some(src) = copy_from {
            body["copy_from"] = serde_json::Value::String(src.to_string());
        }
        let (status, resp_body) =
            self.auth_post_json(&format!("/apps/{}/envs", encode_path(app)), &body)?;
        if !status.is_success() {
            return Err(Self::extract_error(status, &resp_body));
        }
        Ok(())
    }

    fn delete_app(&self, name: &str) -> Result<(), BackendError> {
        let (hdr, val) = self.auth_header();
        let resp = self
            .client
            .delete(self.url(&format!("/apps/{}", encode_path(name))))
            .header(&hdr, &val)
            .send()
            .map_err(|e| BackendError::Other(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp
                .text()
                .map_err(|e| BackendError::Other(e.to_string()))?;
            return Err(Self::extract_error(status, &body));
        }
        Ok(())
    }

    fn delete_env(&self, app: &str, env: &str) -> Result<(), BackendError> {
        let (hdr, val) = self.auth_header();
        let resp = self
            .client
            .delete(self.url(&format!(
                "/apps/{}/envs/{}",
                encode_path(app),
                encode_path(env)
            )))
            .header(&hdr, &val)
            .send()
            .map_err(|e| BackendError::Other(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp
                .text()
                .map_err(|e| BackendError::Other(e.to_string()))?;
            return Err(Self::extract_error(status, &body));
        }
        Ok(())
    }

    fn push_revision(
        &self,
        app: &str,
        env: &str,
        blob: &str,
        parent_rev: u64,
    ) -> Result<RevisionMeta, BackendError> {
        let (status, body) = self.auth_post_json(
            &format!(
                "/apps/{}/envs/{}/revisions",
                encode_path(app),
                encode_path(env)
            ),
            &serde_json::json!({
                "blob": blob,
                "parent_rev": parent_rev,
                "content_hash": null
            }),
        )?;

        if !status.is_success() {
            return Err(Self::extract_error(status, &body));
        }

        #[derive(Deserialize)]
        struct Resp {
            rev_number: u64,
            created_at: String,
            device_id: String,
        }
        let parsed: Resp =
            serde_json::from_str(&body).map_err(|e| BackendError::Other(e.to_string()))?;
        Ok(RevisionMeta {
            rev_number: parsed.rev_number,
            content_hash: None,
            created_at: parsed.created_at,
            device_id: parsed.device_id,
            rollback_of: None,
        })
    }

    fn pull_revision(&self, app: &str, env: &str, rev: &RevSpec) -> Result<Revision, BackendError> {
        let rev_str = match rev {
            RevSpec::Latest => "last".to_string(),
            RevSpec::Number(n) => n.to_string(),
        };
        let (status, body) = self.auth_get(&format!(
            "/apps/{}/envs/{}/revisions/{rev_str}",
            encode_path(app),
            encode_path(env)
        ))?;
        if !status.is_success() {
            return Err(Self::extract_error(status, &body));
        }
        serde_json::from_str(&body).map_err(|e| BackendError::Other(e.to_string()))
    }

    fn list_revisions(&self, app: &str, env: &str) -> Result<Vec<RevisionMeta>, BackendError> {
        let (status, body) = self.auth_get(&format!(
            "/apps/{}/envs/{}/revisions",
            encode_path(app),
            encode_path(env)
        ))?;
        if !status.is_success() {
            return Err(Self::extract_error(status, &body));
        }

        #[derive(Deserialize)]
        struct Resp {
            revisions: Vec<RevisionMeta>,
        }
        let parsed: Resp =
            serde_json::from_str(&body).map_err(|e| BackendError::Other(e.to_string()))?;
        Ok(parsed.revisions)
    }

    fn rollback(&self, app: &str, env: &str, to_rev: u64) -> Result<RevisionMeta, BackendError> {
        let (status, body) = self.auth_post_json(
            &format!(
                "/apps/{}/envs/{}/rollback",
                encode_path(app),
                encode_path(env)
            ),
            &serde_json::json!({"to_rev": to_rev}),
        )?;

        if !status.is_success() {
            return Err(Self::extract_error(status, &body));
        }

        #[derive(Deserialize)]
        struct Resp {
            rev_number: u64,
            copied_from: u64,
        }
        let parsed: Resp =
            serde_json::from_str(&body).map_err(|e| BackendError::Other(e.to_string()))?;
        Ok(RevisionMeta {
            rev_number: parsed.rev_number,
            content_hash: None,
            created_at: String::new(),
            device_id: String::new(),
            rollback_of: Some(parsed.copied_from),
        })
    }

    // --- AK rotation (spec L) ---

    fn rotate_begin(&self, req: &RotateBeginReq) -> Result<RotateStatus, BackendError> {
        let (status, body) = self.auth_post_json(
            "/account/rotate/begin",
            &serde_json::to_value(req).map_err(|e| BackendError::Other(e.to_string()))?,
        )?;
        if !status.is_success() {
            return Err(Self::extract_error(status, &body));
        }
        #[derive(Deserialize)]
        struct Resp {
            new_key_gen: u64,
            stale_count: u64,
        }
        let parsed: Resp =
            serde_json::from_str(&body).map_err(|e| BackendError::Other(e.to_string()))?;
        Ok(RotateStatus {
            in_progress: true,
            current_key_gen: parsed.new_key_gen.saturating_sub(1),
            new_key_gen: Some(parsed.new_key_gen),
            stale_count: parsed.stale_count,
            stale: Vec::new(),
            pending_nonce_ak: None,
            pending_wrapped_ak: None,
        })
    }

    fn rotate_status(&self) -> Result<RotateStatus, BackendError> {
        let (status, body) = self.auth_get("/account/rotate")?;
        if !status.is_success() {
            return Err(Self::extract_error(status, &body));
        }
        serde_json::from_str(&body).map_err(|e| BackendError::Other(e.to_string()))
    }

    fn rotate_put_blob(
        &self,
        app: &str,
        env: &str,
        rev: u64,
        blob: &str,
        key_gen: u64,
    ) -> Result<(), BackendError> {
        let (hdr, val) = self.auth_header();
        let resp = self
            .client
            .put(self.url(&format!(
                "/apps/{}/envs/{}/revisions/{rev}/blob",
                encode_path(app),
                encode_path(env)
            )))
            .header(&hdr, &val)
            .json(&serde_json::json!({"blob": blob, "key_gen": key_gen}))
            .send()
            .map_err(|e| BackendError::Other(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp
                .text()
                .map_err(|e| BackendError::Other(e.to_string()))?;
            return Err(Self::extract_error(status, &body));
        }
        Ok(())
    }

    fn rotate_complete(&self) -> Result<u64, BackendError> {
        let (status, body) =
            self.auth_post_json("/account/rotate/complete", &serde_json::json!({}))?;
        if !status.is_success() {
            return Err(Self::extract_error(status, &body));
        }
        #[derive(Deserialize)]
        struct Resp {
            current_key_gen: u64,
        }
        let parsed: Resp =
            serde_json::from_str(&body).map_err(|e| BackendError::Other(e.to_string()))?;
        Ok(parsed.current_key_gen)
    }
}
