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
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_flush_interval_secs")]
    pub flush_interval_secs: u64,
    #[serde(default = "default_flush_count")]
    pub flush_count: usize,
}

fn default_flush_interval_secs() -> u64 {
    5
}

fn default_flush_count() -> usize {
    100
}

fn default_log_level() -> String {
    "warn".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogType {
    Console,
    File,
    None,
}

fn default_log_type() -> LogType {
    LogType::None
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

        let config: Config =
            serde_yaml::from_str(&content).with_context(|| "Failed to parse config file")?;

        Ok(config)
    }

    pub fn get_listen_addr(&self) -> Result<SocketAddr> {
        let addr: IpAddr = self
            .listen
            .addr
            .parse()
            .with_context(|| format!("Invalid listen address: {}", self.listen.addr))?;
        Ok(SocketAddr::new(addr, self.listen.port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_parsing() {
        let yaml = r#"
log:
  log_type: console
  level: info

listen:
  addr: "127.0.0.1"
  port: 1080

rules:
  - match_patterns:
      - "*.google.com"
    forward_to: "socks5://127.0.0.1:1080"
"#;

        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(config.log.log_type, LogType::Console));
        assert_eq!(config.log.level, "info");
        assert_eq!(config.log.flush_interval_secs, 5); // default
        assert_eq!(config.log.flush_count, 100); // default

        assert_eq!(config.listen.addr, "127.0.0.1");
        assert_eq!(config.listen.port, 1080);
        assert_eq!(
            config.get_listen_addr().unwrap(),
            "127.0.0.1:1080".parse::<SocketAddr>().unwrap()
        );

        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].match_patterns[0], "*.google.com");
        assert_eq!(config.rules[0].forward_to, "socks5://127.0.0.1:1080");
    }

    #[test]
    fn test_config_defaults() {
        let yaml = r#"
log:
  file: "app.log"

listen:
  port: 8080

rules: []
"#;

        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(config.log.log_type, LogType::None)); // default
        assert_eq!(config.log.level, "warn"); // default
        assert_eq!(config.listen.addr, "127.0.0.1"); // default
        assert_eq!(config.listen.port, 8080);
    }
}
