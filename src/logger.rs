use anyhow::{Context, Result};
use std::fs::OpenOptions;

use crate::config::LogConfig;

#[cfg(windows)]
fn alloc_console() -> Result<()> {
    use windows::Win32::System::Console::AllocConsole;
    unsafe {
        AllocConsole()?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn alloc_console() -> Result<()> {
    Ok(())
}

pub fn setup_logger(config: &LogConfig) -> Result<()> {
    let env = env_logger::Env::default()
        .filter_or("RUST_LOG", &config.level);

    match config.log_type {
        crate::config::LogType::Console => {
            alloc_console()?;
            env_logger::Builder::from_env(env)
                .format_timestamp_secs()
                .init();
        }
        crate::config::LogType::File => {
            let log_file = config.file.as_ref()
                .ok_or_else(|| anyhow::anyhow!("Log file path is required when log_type is file"))?;

            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_file)
                .with_context(|| format!("Failed to open log file: {}", log_file))?;

            env_logger::Builder::from_env(env)
                .format_timestamp_secs()
                .target(env_logger::Target::Pipe(Box::new(file)))
                .init();
        }
    }

    Ok(())
}
