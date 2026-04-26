use std::str::FromStr;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt::time::LocalTime, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

impl FromStr for LogLevel {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "trace" => Ok(LogLevel::Trace),
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" => Ok(LogLevel::Warn),
            "error" => Ok(LogLevel::Error),
            _ => Err(()),
        }
    }
}

impl LogLevel {
    pub fn to_level_filter(self) -> LevelFilter {
        match self {
            LogLevel::Trace => LevelFilter::TRACE,
            LogLevel::Debug => LevelFilter::DEBUG,
            LogLevel::Info => LevelFilter::INFO,
            LogLevel::Warn => LevelFilter::WARN,
            LogLevel::Error => LevelFilter::ERROR,
        }
    }
}

const LOG_TIME_FORMAT: &[time::format_description::FormatItem<'static>] = time::macros::format_description!(
    "[year repr:last_two]-[month]-[day] [hour]:[minute]:[second]"
);

pub fn init_logger(log_level_str: &str) {
    let level = LogLevel::from_str(log_level_str).unwrap_or_default();
    let filter = tracing_subscriber::filter::Targets::new()
        .with_targets(vec![
            ("server_mieru_rs", level.to_level_filter()),
            ("server_mieru", level.to_level_filter()),
            ("server", level.to_level_filter()),
        ])
        .with_default(LevelFilter::INFO);
    let registry = tracing_subscriber::registry();
    registry
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_timer(LocalTime::new(LOG_TIME_FORMAT)),
        )
        .init();
}

pub mod log {
    pub use tracing::{debug, info, warn};
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::level_filters::LevelFilter;

    #[test]
    fn test_log_level_from_str_valid() {
        assert_eq!("trace".parse::<LogLevel>(), Ok(LogLevel::Trace));
        assert_eq!("debug".parse::<LogLevel>(), Ok(LogLevel::Debug));
        assert_eq!("info".parse::<LogLevel>(), Ok(LogLevel::Info));
        assert_eq!("warn".parse::<LogLevel>(), Ok(LogLevel::Warn));
        assert_eq!("error".parse::<LogLevel>(), Ok(LogLevel::Error));
    }

    #[test]
    fn test_log_level_from_str_case_insensitive() {
        assert_eq!("TRACE".parse::<LogLevel>(), Ok(LogLevel::Trace));
        assert_eq!("DEBUG".parse::<LogLevel>(), Ok(LogLevel::Debug));
        assert_eq!("INFO".parse::<LogLevel>(), Ok(LogLevel::Info));
        assert_eq!("WARN".parse::<LogLevel>(), Ok(LogLevel::Warn));
        assert_eq!("ERROR".parse::<LogLevel>(), Ok(LogLevel::Error));
        assert_eq!("Trace".parse::<LogLevel>(), Ok(LogLevel::Trace));
        assert_eq!("Debug".parse::<LogLevel>(), Ok(LogLevel::Debug));
        assert_eq!("Info".parse::<LogLevel>(), Ok(LogLevel::Info));
        assert_eq!("Warn".parse::<LogLevel>(), Ok(LogLevel::Warn));
        assert_eq!("Error".parse::<LogLevel>(), Ok(LogLevel::Error));
    }

    #[test]
    fn test_log_level_from_str_invalid() {
        assert_eq!("invalid".parse::<LogLevel>(), Err(()));
        assert_eq!("".parse::<LogLevel>(), Err(()));
        assert_eq!("verbose".parse::<LogLevel>(), Err(()));
        assert_eq!("critical".parse::<LogLevel>(), Err(()));
    }

    #[test]
    fn test_log_level_to_level_filter() {
        assert_eq!(LogLevel::Trace.to_level_filter(), LevelFilter::TRACE);
        assert_eq!(LogLevel::Debug.to_level_filter(), LevelFilter::DEBUG);
        assert_eq!(LogLevel::Info.to_level_filter(), LevelFilter::INFO);
        assert_eq!(LogLevel::Warn.to_level_filter(), LevelFilter::WARN);
        assert_eq!(LogLevel::Error.to_level_filter(), LevelFilter::ERROR);
    }

    #[test]
    fn test_log_level_default() {
        let default_level = LogLevel::default();
        assert_eq!(default_level, LogLevel::Info);
    }

    #[test]
    fn test_log_time_format_is_valid() {
        // Verify the format has entries (non-empty) and can be used to construct a LocalTime
        assert!(!LOG_TIME_FORMAT.is_empty());
        let _timer = tracing_subscriber::fmt::time::LocalTime::new(LOG_TIME_FORMAT);
    }
}
