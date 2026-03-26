use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub log: LogConfig,
    pub listen: ListenConfig,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_log_type")]
    pub log_type: LogType,
    pub file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogType {
    Console,
    File,
}

fn default_log_type() -> LogType {
    LogType::Console
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenConfig {
    #[serde(default = "default_listen_addr")]
    pub addr: String,
    #[serde(default = "default_listen_port")]
    pub port: u16,
}

fn default_listen_addr() -> String {
    "127.0.0.1".to_string()
}

fn default_listen_port() -> u16 {
    1080
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub match_patterns: Vec<String>,
    pub forward_to: String,
}

impl Config {
    pub async fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = tokio::fs::read_to_string(path.as_ref())
            .await
            .with_context(|| format!("Failed to read config file: {}", path.as_ref().display()))?;

        let config: Config = serde_yaml::from_str(&content)
            .with_context(|| "Failed to parse config file")?;

        Ok(config)
    }

    pub fn get_listen_addr(&self) -> Result<SocketAddr> {
        let addr: IpAddr = self.listen.addr.parse()
            .with_context(|| format!("Invalid listen address: {}", self.listen.addr))?;
        Ok(SocketAddr::new(addr, self.listen.port))
    }
}
