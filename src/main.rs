mod config;
mod logger;
mod matcher;
mod proxy_client;
mod socks5_server;
mod tray;

use anyhow::{Context, Result};
use config::Config;
use matcher::RuleMatcher;
use proxy_client::ProxyConfig;
use socks5_server::Socks5Server;
use std::path::Path;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = Path::new("config.yaml");
    let config = Config::from_file(config_path)
        .with_context(|| "Failed to load config")?;

    logger::setup_logger(&config.log)?;

    log::info!("Starting Simple Forwarder...");

    let (tx, rx) = mpsc::channel::<()>(100);

    let mut rules = Vec::new();
    for rule in &config.rules {
        let matcher = RuleMatcher::new(rule.match_patterns.clone());
        let proxy_config = ProxyConfig::from_url(&rule.forward_to)?;
        rules.push((matcher, proxy_config));
        log::info!("Loaded rule: {} patterns -> {}", rule.match_patterns.len(), rule.forward_to);
    }

    let listen_addr = config.get_listen_addr()?;

    let _tray = tray::TrayManager::new(rx)?;

    let mut server = Socks5Server::new(listen_addr, tx, rules).await?;

    log::info!("Simple Forwarder is running...");

    server.run().await?;

    Ok(())
}
