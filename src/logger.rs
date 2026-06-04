use anyhow::{Context, Result};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::time::{Duration, Instant};

use crate::config::LogConfig;

#[cfg(windows)]
fn alloc_console() -> Result<()> {
    use windows::Win32::Storage::FileSystem::FILE_GENERIC_WRITE;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::Console::{
        AllocConsole, FreeConsole, GetConsoleWindow, GetStdHandle, STD_ERROR_HANDLE,
        STD_OUTPUT_HANDLE, SetStdHandle,
    };
    use windows::core::w;

    unsafe {
        // In debug builds we usually already have a console. Only allocate one
        // for GUI runs that don't have an attached console yet.
        if GetConsoleWindow().0.is_null() {
            AllocConsole()?;

            let handle = match CreateFileW(
                w!("CONOUT$"),
                FILE_GENERIC_WRITE.0,
                FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            ) {
                Ok(h) => h,
                Err(e) => {
                    let _ = FreeConsole();
                    return Err(e.into());
                }
            };

            // Only redirect standard handles if they are currently invalid or null
            let stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE)?;
            if (stdout_handle.is_invalid() || stdout_handle.0.is_null())
                && let Err(e) = SetStdHandle(STD_OUTPUT_HANDLE, handle)
            {
                eprintln!("AllocConsole: failed to set STD_OUTPUT_HANDLE: {:?}", e);
            }

            let stderr_handle = GetStdHandle(STD_ERROR_HANDLE)?;
            if (stderr_handle.is_invalid() || stderr_handle.0.is_null())
                && let Err(e) = SetStdHandle(STD_ERROR_HANDLE, handle)
            {
                eprintln!("AllocConsole: failed to set STD_ERROR_HANDLE: {:?}", e);
            }
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
    let env = env_logger::Env::default().filter_or("RUST_LOG", &config.level);

    let mut builder = env_logger::Builder::from_env(env);

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
            let log_file = config.file.as_ref().ok_or_else(|| {
                anyhow::anyhow!("Log file path is required when log_type is file")
            })?;

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

            builder
                .target(env_logger::Target::Pipe(Box::new(flushing_writer)))
                .init();
        }
    }

    Ok(())
}
