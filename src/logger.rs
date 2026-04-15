use anyhow::{Context, Result};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::time::{Duration, Instant};

use crate::config::LogConfig;

#[cfg(windows)]
fn alloc_console() -> Result<()> {
    use windows::Win32::System::Console::{AllocConsole, GetConsoleWindow};

    unsafe {
        // In debug builds we usually already have a console. Only allocate one
        // for GUI runs that don't have an attached console yet.
        if GetConsoleWindow().0.is_null() {
            AllocConsole()?;
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn alloc_console() -> Result<()> {
    Ok(())
}

struct FlushingWriter {
    writer: BufWriter<std::fs::File>,
    count: usize,
    flush_count: usize,
    flush_interval: Duration,
    last_flush: Instant,
}

impl FlushingWriter {
    fn new(file: std::fs::File, flush_count: usize, flush_interval: Duration) -> Self {
        Self {
            writer: BufWriter::new(file),
            count: 0,
            flush_count,
            flush_interval,
            last_flush: Instant::now(),
        }
    }
}

impl Write for FlushingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let n = self.writer.write(buf)?;
        
        // Each log entry results in one or more write calls.
        self.count += 1;
        if self.count >= self.flush_count || self.last_flush.elapsed() >= self.flush_interval {
            self.writer.flush()?;
            self.count = 0;
            self.last_flush = Instant::now();
        }
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
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

    #[cfg(debug_assertions)]
    let effective_log_type = match config.log_type {
        crate::config::LogType::None => crate::config::LogType::Console,
        ref other => other.clone(),
    };

    #[cfg(not(debug_assertions))]
    let effective_log_type = config.log_type.clone();

    match effective_log_type {
        crate::config::LogType::None => {
            // Do nothing, no logger initialized and no console allocated
        }
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

            let flushing_writer = FlushingWriter::new(
                file,
                config.flush_count,
                Duration::from_secs(config.flush_interval_secs),
            );

            builder.target(env_logger::Target::Pipe(Box::new(flushing_writer))).init();
        }
    }

    Ok(())
}
