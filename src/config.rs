use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
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

/// YAML parse failure with the source location reported by libyaml.
#[derive(Debug)]
pub(crate) struct YamlParseError {
    pub path: String,
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub message: String,
}

impl YamlParseError {
    fn from_serde(path: &Path, err: serde_yaml::Error) -> Self {
        let loc = err.location();
        Self {
            path: path.display().to_string(),
            line: loc.as_ref().map(|l| l.line()),
            column: loc.as_ref().map(|l| l.column()),
            message: err.to_string(),
        }
    }

    /// User-facing text for the config-error dialog.
    pub(crate) fn dialog_text(&self) -> String {
        match (self.line, self.column) {
            (Some(line), Some(column)) => format!(
                "A syntax error was found in:\n\n{}\n\nLine: {}\nColumn: {}\n\n{}",
                self.path, line, column, self.message
            ),
            _ => format!("Failed to parse:\n\n{}\n\n{}", self.path, self.message),
        }
    }
}

impl fmt::Display for YamlParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.line, self.column) {
            (Some(line), Some(column)) => write!(
                f,
                "Failed to parse {}: syntax error at line {}, column {}: {}",
                self.path, line, column, self.message
            ),
            _ => write!(f, "Failed to parse {}: {}", self.path, self.message),
        }
    }
}

impl std::error::Error for YamlParseError {}

impl Config {
    pub(crate) fn parse_yaml(
        content: &str,
        path: &Path,
    ) -> std::result::Result<Self, YamlParseError> {
        serde_yaml::from_str(content).map_err(|err| YamlParseError::from_serde(path, err))
    }

    pub async fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let content = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        Self::parse_yaml(&content, path).map_err(Into::into)
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

    #[test]
    fn test_yaml_syntax_error_reports_line_and_column() {
        // `@` cannot start a YAML token; libyaml reports this at line 2, column 1.
        let yaml = "log:\n@invalid\n";
        let err = Config::parse_yaml(yaml, Path::new("config.yaml")).unwrap_err();
        assert_eq!(err.line, Some(2));
        assert_eq!(err.column, Some(1));
        assert!(err.path.contains("config.yaml"));
    }

    #[test]
    fn test_yaml_syntax_error_dialog_text_includes_location() {
        let err = YamlParseError {
            path: "D:\\app\\config.yaml".to_string(),
            line: Some(12),
            column: Some(5),
            message: "found unexpected end of stream".to_string(),
        };
        let text = err.dialog_text();
        assert!(text.contains("D:\\app\\config.yaml"));
        assert!(text.contains("Line: 12"));
        assert!(text.contains("Column: 5"));
        assert!(text.contains("found unexpected end of stream"));
    }

    #[test]
    fn test_yaml_error_without_location_omits_line_column() {
        let err = YamlParseError {
            path: "config.yaml".to_string(),
            line: None,
            column: None,
            message: "EOF while parsing a value".to_string(),
        };
        let text = err.dialog_text();
        assert!(text.contains("config.yaml"));
        assert!(!text.contains("Line:"));
        assert!(!text.contains("Column:"));
        assert!(text.contains("EOF while parsing a value"));
    }
}
