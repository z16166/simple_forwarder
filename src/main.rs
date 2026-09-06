#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;
mod connection_tracker;
mod etw_resolver;
mod logger;
mod matcher;
mod proxy_client;
mod proxy_server;
mod stats;
mod traffic_window;
mod tray;
mod util;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use config::Config;
use matcher::RuleMatcher;
use notify::{RecursiveMode, Watcher};
use proxy_client::ProxyConfig;
use proxy_server::ProxyServer;
use std::sync::Arc;
use std::sync::OnceLock;

/// Cached result of whether this process is running with administrator
/// privileges (UAC-elevated token, or UAC disabled + admin token).
/// Determined once at startup and never changes.
static IS_ADMIN: OnceLock<bool> = OnceLock::new();

/// Returns `true` if the process is running with administrator privileges.
pub(crate) fn is_admin() -> bool {
    *IS_ADMIN.get_or_init(|| false)
}

/// Detect whether the current process token has administrator privileges.
///
/// Uses `CheckTokenMembership` with the built-in Administrators SID, which
/// correctly handles both UAC-elevated tokens and the case where UAC is
/// disabled but the user is a member of the local Administrators group.
#[cfg(windows)]
fn detect_admin() -> bool {
    use windows::Win32::Foundation::BOOL;
    use windows::Win32::Security::{
        AllocateAndInitializeSid, CheckTokenMembership, FreeSid, PSID, SECURITY_NT_AUTHORITY,
    };

    unsafe {
        // Build the well-known SID for the local Administrators group:
        // S-1-5-32-544
        let mut sid = PSID(std::ptr::null_mut());
        let authority = SECURITY_NT_AUTHORITY;
        let ok = AllocateAndInitializeSid(
            &authority, 2,          // sub-authority count
            0x00000020, // SECURITY_BUILTIN_RID
            0x00000220, // DOMAIN_ALIAS_RID_ADMINS
            0, 0, 0, 0, 0, 0, &mut sid,
        );
        if ok.is_err() {
            return false;
        }

        let mut is_member = BOOL(0);
        let result = CheckTokenMembership(None, sid, &mut is_member);
        FreeSid(sid);
        result.is_ok() && is_member.as_bool()
    }
}

#[cfg(not(windows))]
fn detect_admin() -> bool {
    false
}

fn main() {
    // Determine admin privileges once at startup so the rest of the app
    // can query `is_admin()` without re-checking.
    let _ = IS_ADMIN.set(detect_admin());

    // Build the tokio runtime manually instead of using #[tokio::main] so
    // the main thread is NOT a tokio worker. This lets us run the Win32
    // message loop (GetMessageW) on the main thread without consuming a
    // worker thread from the pool.
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            #[cfg(windows)]
            unsafe {
                use windows::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
                use windows::core::HSTRING;
                let _ = MessageBoxW(
                    None,
                    &HSTRING::from(format!("Failed to initialize:\n\n{}", e)),
                    &HSTRING::from(&format!("{} - Startup Error", tray::APP_NAME)),
                    MB_OK | MB_ICONERROR,
                );
            }
            #[cfg(not(windows))]
            eprintln!("Fatal error: {}", e);
            std::process::exit(1);
        }
    };

    match rt.block_on(run_app_init()) {
        Ok((_guard, tray_manager, exe_resolver)) => {
            // Run the Win32 message loop on the main thread.
            // Returns only when the user clicks Quit.
            tray_manager.run_message_loop();
            exe_resolver.cleanup();
            log::info!("Shutting down.");
            log::logger().flush();
            std::process::exit(0);
        }
        Err(e) => {
            #[cfg(windows)]
            unsafe {
                use windows::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
                use windows::core::HSTRING;
                let text = match e.downcast_ref::<config::YamlParseError>() {
                    Some(yaml_err) => yaml_err.dialog_text(),
                    None => format!("{} failed to start:\n\n{}", tray::APP_NAME, e),
                };
                let _ = MessageBoxW(
                    None,
                    &HSTRING::from(text),
                    &HSTRING::from(&format!("{} - Startup Error", tray::APP_NAME)),
                    MB_OK | MB_ICONERROR,
                );
            }
            #[cfg(not(windows))]
            eprintln!("Fatal error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Container for objects that must stay alive for the app's lifetime
/// (single-instance lock, etc.).
struct AppGuard {
    _instance: single_instance::SingleInstance,
}

async fn run_app_init() -> Result<(AppGuard, tray::TrayManager, etw_resolver::ExeResolver)> {
    // Single instance check
    let _instance = {
        use single_instance::SingleInstance;
        let instance = SingleInstance::new("SimpleForwarderSingleInstanceMutex")
            .with_context(|| "Failed to create single instance lock")?;
        if !instance.is_single() {
            #[cfg(windows)]
            unsafe {
                use windows::Win32::UI::WindowsAndMessaging::{MB_ICONWARNING, MB_OK, MessageBoxW};
                use windows::core::HSTRING;
                let _ = MessageBoxW(
                    None,
                    &HSTRING::from(format!(
                        "Another instance of {} is already running.\n\nPlease check the system tray.",
                        tray::APP_NAME
                    )),
                    &HSTRING::from(&format!("{} - Already Running", tray::APP_NAME)),
                    MB_OK | MB_ICONWARNING,
                );
            }
            std::process::exit(0);
        }
        instance
    };

    let exe_path =
        std::env::current_exe().with_context(|| "Failed to get current executable path")?;
    let exe_dir = exe_path
        .parent()
        .with_context(|| "Failed to get executable directory")?;
    let config_path = exe_dir.join("config.yaml");

    let config = Config::from_file(&config_path)
        .await
        .with_context(|| format!("Failed to load config from {:?}", config_path))?;

    logger::setup_logger(&config.log)?;

    log::info!("Starting Simple Forwarder...");

    let initial_rules = parse_rules(&config)?;
    let rules_arc = Arc::new(ArcSwap::from_pointee(initial_rules));
    let rules_for_server = rules_arc.clone();

    let listen_addr = config.get_listen_addr()?;

    let stats = stats::TrafficStats::new(listen_addr.to_string());
    let stats_for_server = stats.clone();
    let stats_for_tray = stats.clone();

    let tracker = connection_tracker::ConnectionTracker::new();
    let tracker_for_server = tracker.clone();
    let tracker_for_tray = tracker.clone();

    let exe_resolver = etw_resolver::ExeResolver::new(listen_addr.port());

    let tray_manager = tray::TrayManager::new(stats_for_tray, tracker_for_tray)?;
    let server = ProxyServer::new(
        listen_addr,
        rules_for_server,
        stats_for_server,
        tracker_for_server,
        exe_resolver.clone(),
    )
    .await?;

    // Setup configuration watcher
    let rules_for_watcher = rules_arc.clone();
    let config_path_for_watcher = config_path.to_path_buf();

    // Issue 11: use try_send instead of blocking_send to avoid blocking the
    // notify callback thread if the channel is full (capacity=1).
    let (watch_tx, mut watch_rx) = tokio::sync::mpsc::channel(1);

    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(event) = res
            && event.kind.is_modify()
        {
            let _ = watch_tx.try_send(());
        }
    })?;

    watcher.watch(&config_path, RecursiveMode::NonRecursive)?;

    tokio::spawn(async move {
        // Keep watcher alive
        let _watcher = watcher;
        while watch_rx.recv().await.is_some() {
            log::info!("Config file changed, reloading...");
            // Small delay to ensure file is completely written
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            // Issue 11: wrap config reload in a timeout to prevent hanging
            // if the file is on a network share or locked.
            let reload_result = tokio::time::timeout(
                tokio::time::Duration::from_secs(5),
                Config::from_file(&config_path_for_watcher),
            )
            .await;

            match reload_result {
                Ok(Ok(new_config)) => match parse_rules(&new_config) {
                    Ok(new_rules) => {
                        rules_for_watcher.store(Arc::new(new_rules));
                        log::info!("Rules reloaded successfully");
                    }
                    Err(e) => log::error!("Failed to parse new rules: {}", e),
                },
                Ok(Err(e)) => {
                    log::error!("Failed to reload config: {}", e);
                    if let Some(yaml_err) = e.downcast_ref::<config::YamlParseError>() {
                        tray::show_config_parse_error(yaml_err);
                    }
                }
                Err(_) => {
                    log::error!("Config reload timed out (file may be locked or on network share)")
                }
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

    // Return ownership to main() — the message loop runs on the main thread
    // outside the runtime, so no tokio worker is consumed.
    Ok((AppGuard { _instance }, tray_manager, exe_resolver))
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
