use anyhow::Result;
use async_trait::async_trait;
use chrono::{offset::Utc, DateTime};
use ethers_core::types::H160;
use openidconnect::{core::CoreClientMetadata, Nonce, RegistrationAccessToken};
use serde::{Deserialize, Serialize};

#[cfg(not(target_arch = "wasm32"))]
mod redis;
#[cfg(not(target_arch = "wasm32"))]
pub use redis::RedisClient;
#[cfg(target_arch = "wasm32")]
mod cf;
#[cfg(target_arch = "wasm32")]
pub use cf::CFClient;

const KV_CLIENT_PREFIX: &str = "clients";
const KV_SESSION_PREFIX: &str = "sessions";
pub const ENTRY_LIFETIME: usize = 30;
pub const SESSION_LIFETIME: u64 = 300; // 5min
pub const SESSION_COOKIE_NAME: &str = "session";

#[derive(Clone, Serialize, Deserialize)]
pub struct CodeEntry {
    pub exchange_count: usize,
    pub address: H160,
    pub nonce: Option<Nonce>,
    pub client_id: String,
    pub auth_time: DateTime<Utc>,
    pub chain_id: Option<u64>, // TODO temporary, for transition purposes
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ClientEntry {
    pub secret: String,
    pub metadata: CoreClientMetadata,
    pub access_token: Option<RegistrationAccessToken>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SessionEntry {
    pub siwe_nonce: String,
    pub oidc_nonce: Option<Nonce>,
    pub secret: String,
    pub signin_count: u64,
}

// Using a trait to easily pass async functions with async_trait
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait DBClient {
    async fn set_client(&self, client_id: String, client_entry: ClientEntry) -> Result<()>;
    async fn get_client(&self, client_id: String) -> Result<Option<ClientEntry>>;
    async fn delete_client(&self, client_id: String) -> Result<()>;
    async fn set_code(&self, code: String, code_entry: CodeEntry) -> Result<()>;
    async fn get_code(&self, code: String) -> Result<Option<CodeEntry>>;
    async fn set_session(&self, id: String, entry: SessionEntry) -> Result<()>;
    async fn get_session(&self, id: String) -> Result<Option<SessionEntry>>;
}
