use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
};
use url::Url;

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub address: IpAddr,
    pub port: u16,
    pub base_url: Url,
    pub rsa_pem: Option<String>,
    pub redis_url: Url,
    pub default_clients: HashMap<String, String>,
    // TODO secret is more complicated than that, and needs to be in the well-known config
    pub require_secret: bool,
    pub eth_provider: Option<Url>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            address: Ipv4Addr::new(127, 0, 0, 1).into(),
            port: 8000,
            base_url: Url::parse("http://127.0.0.1:8000").unwrap(),
            rsa_pem: None,
            redis_url: Url::parse("redis://localhost").unwrap(),
            default_clients: HashMap::default(),
            require_secret: false,
            eth_provider: None,
        }
    }
}
