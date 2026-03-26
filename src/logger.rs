use anyhow::{Context, Result};
use std::fs::OpenOptions;

use crate::config::LogConfig;

pub fn setup_logger(config: &LogConfig) -> Result<()> {
    let env = env_logger::Env::default()
        .filter_or("RUST_LOG", "info");

    match config.log_type {
        crate::config::LogType::Console => {
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
