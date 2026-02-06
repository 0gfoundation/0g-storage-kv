use task_executor::TaskExecutor;
use tracing::Level;
use tracing_subscriber::EnvFilter;

const LOG_RELOAD_PERIOD_SEC: u64 = 30;

pub fn configure(logfile: &str, executor: TaskExecutor) {
    let builder = tracing_subscriber::fmt()
        .with_max_level(Level::TRACE)
        .with_env_filter(EnvFilter::default())
        // .with_file(true)
        // .with_line_number(true)
        // .with_thread_names(true)
        .with_filter_reloading();

    let handle = builder.reload_handle();
    builder.init();

    let logfile = logfile.trim_end().to_string();

    // load config synchronously
    let mut config = std::fs::read_to_string(&logfile)
        .unwrap_or_default()
        .trim_end()
        .to_string();
    let _ = handle.reload(&config);

    // periodically check for config changes
    executor.spawn(
        async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(LOG_RELOAD_PERIOD_SEC));

            loop {
                interval.tick().await;

                let new_config = match tokio::fs::read_to_string(&logfile).await {
                    Ok(c) => c.trim_end().to_string(),
                    Err(e) => {
                        println!("Unable to read log file {}: {:?}", logfile, e);
                        continue;
                    }
                };

                if new_config == config {
                    continue;
                }

                println!("Updating log config to {:?}", new_config);

                match handle.reload(&new_config) {
                    Ok(()) => config = new_config,
                    Err(e) => {
                        println!("Failed to load new config: {:?}", e);
                    }
                }
            }
        },
        "log_reload",
    );
}
