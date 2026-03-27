#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;
mod logger;
mod matcher;
mod proxy_client;
mod proxy_server;
mod tray;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use config::Config;
use matcher::RuleMatcher;
use notify::{RecursiveMode, Watcher};
use proxy_client::ProxyConfig;
use proxy_server::ProxyServer;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = Path::new("config.yaml");
    let config = Config::from_file(config_path).await
        .with_context(|| "Failed to load config")?;

    logger::setup_logger(&config.log)?;

    log::info!("Starting Simple Forwarder...");

    let (tx, rx) = mpsc::channel::<()>(100);

    let initial_rules = parse_rules(&config)?;
    let rules_arc = Arc::new(ArcSwap::from_pointee(initial_rules));
    let rules_for_server = rules_arc.clone();

    let listen_addr = config.get_listen_addr()?;

    let tray_manager = tray::TrayManager::new(rx)?;
    let server = ProxyServer::new(listen_addr, tx, rules_for_server).await?;

    // Setup configuration watcher
    let rules_for_watcher = rules_arc.clone();
    let config_path_for_watcher = config_path.to_path_buf();

    let (watch_tx, mut watch_rx) = tokio::sync::mpsc::channel(1);

    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(event) = res {
            if event.kind.is_modify() {
                let _ = watch_tx.blocking_send(());
            }
        }
    })?;

    watcher.watch(config_path, RecursiveMode::NonRecursive)?;

    tokio::spawn(async move {
        // Keep watcher alive
        let _watcher = watcher;
        while let Some(_) = watch_rx.recv().await {
            log::info!("Config file changed, reloading...");
            // Small delay to ensure file is completely written
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            match Config::from_file(&config_path_for_watcher).await {
                Ok(new_config) => {
                    match parse_rules(&new_config) {
                        Ok(new_rules) => {
                            rules_for_watcher.store(Arc::new(new_rules));
                            log::info!("Rules reloaded successfully");
                        }
                        Err(e) => log::error!("Failed to parse new rules: {}", e),
                    }
                }
                Err(e) => log::error!("Failed to reload config: {}", e),
            }
        }
    });

    log::info!("Simple Forwarder is running...");

    let mut server = server;
    tokio::spawn(async move {
        if let Err(e) = server.run().await {
            log::error!("Proxy server error: {}", e);
        }
    });

    tray_manager.run_message_loop();

    Ok(())
}

fn parse_rules(config: &Config) -> Result<Vec<(RuleMatcher, ProxyConfig)>> {
    let mut rules = Vec::new();
    for rule in &config.rules {
        let matcher = RuleMatcher::new(rule.match_patterns.clone());
        let proxy_config = ProxyConfig::from_url(&rule.forward_to)?;
        rules.push((matcher, proxy_config));
    }
    Ok(rules)
}
