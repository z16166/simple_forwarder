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

    let builder = env_logger::Builder::from_env(env);
    let mut builder = builder;
    
    builder.format(|buf, record| {
        use std::io::Write;
        let now = chrono::Local::now();
        let level = record.level();
        let style = buf.default_level_style(level);
        
        writeln!(
            buf,
            "[{} {}{:5}{} {}] {}",
            now.format("%Y-%m-%dT%H:%M:%S"),
            style.render(),
            level,
            style.render_reset(),
            record.target(),
            record.args()
        )
    });

    match config.log_type {
        crate::config::LogType::Console => {
            alloc_console()?;
            builder.init();
        }
        crate::config::LogType::File => {
            let log_file = config.file.as_ref()
                .ok_or_else(|| anyhow::anyhow!("Log file path is required when log_type is file"))?;

            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_file)
                .with_context(|| format!("Failed to open log file: {}", log_file))?;

            builder.target(env_logger::Target::Pipe(Box::new(file))).init();
        }
    }

    Ok(())
}
