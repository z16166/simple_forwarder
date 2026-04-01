#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;
mod logger;
mod matcher;
mod proxy_client;
mod proxy_server;
mod stats;
mod tray;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use config::Config;
use matcher::RuleMatcher;
use notify::{RecursiveMode, Watcher};
use proxy_client::ProxyConfig;
use proxy_server::ProxyServer;
use std::sync::Arc;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<()> {
    if let Err(e) = run_app().await {
        #[cfg(windows)]
        unsafe {
            use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_OK, MB_ICONERROR};
            use windows::core::HSTRING;
            let _ = MessageBoxW(
                None,
                &HSTRING::from(format!("Simple Forwarder failed to start:\n\n{}", e)),
                &HSTRING::from("Simple Forwarder - Startup Error"),
                MB_OK | MB_ICONERROR,
            );
        }
        return Err(e);
    }
    Ok(())
}

async fn run_app() -> Result<()> {
    // Single instance check
    let _instance = {
        use single_instance::SingleInstance;
        let instance = SingleInstance::new("SimpleForwarderSingleInstanceMutex")
            .with_context(|| "Failed to create single instance lock")?;
        if !instance.is_single() {
            #[cfg(windows)]
            unsafe {
                use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_OK, MB_ICONWARNING};
                use windows::core::HSTRING;
                let _ = MessageBoxW(
                    None,
                    &HSTRING::from("Another instance of Simple Forwarder is already running.\n\nPlease check the system tray."),
                    &HSTRING::from("Simple Forwarder - Already Running"),
                    MB_OK | MB_ICONWARNING,
                );
            }
            return Ok(());
        }
        instance
    };

    let exe_path = std::env::current_exe().with_context(|| "Failed to get current executable path")?;
    let exe_dir = exe_path.parent().with_context(|| "Failed to get executable directory")?;
    let config_path = exe_dir.join("config.yaml");

    let config = Config::from_file(&config_path).await
        .with_context(|| format!("Failed to load config from {:?}", config_path))?;

    logger::setup_logger(&config.log)?;

    log::info!("Starting Simple Forwarder...");

    let (tx, rx) = mpsc::channel::<()>(100);

    let initial_rules = parse_rules(&config)?;
    let rules_arc = Arc::new(ArcSwap::from_pointee(initial_rules));
    let rules_for_server = rules_arc.clone();

    let listen_addr = config.get_listen_addr()?;

    let stats = stats::TrafficStats::new();
    let stats_for_server = stats.clone();
    let stats_for_tray = stats.clone();

    let tray_manager = tray::TrayManager::new(rx, stats_for_tray)?;
    let server = ProxyServer::new(listen_addr, tx, rules_for_server, stats_for_server).await?;

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

    watcher.watch(&config_path, RecursiveMode::NonRecursive)?;

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

    // run_message_loop() only returns when the user clicks Quit.
    // The tokio runtime's thread pool (proxy server, config watcher, activity task)
    // would otherwise keep the process—and its console window—alive indefinitely.
    // Force a clean exit so everything (including the console) is released immediately.
    log::info!("Shutting down.");
    std::process::exit(0);
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
