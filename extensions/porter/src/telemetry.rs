// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail};
use tracing_subscriber::EnvFilter;

pub struct Config {
    filter: EnvFilter,
    format: Format,
}

enum Format {
    Text,
    Json,
}

impl Config {
    pub fn new(level: &str, format: &str) -> Result<Self> {
        let level = if level == "none" { "off" } else { level };
        let filter = EnvFilter::try_new(format!("agentio_porter={level}"))
            .context("invalid AGENTIO_LOG_LEVEL")?;
        let format = match format {
            "text" => Format::Text,
            "json" => Format::Json,
            _ => bail!("AGENTIO_LOG_FORMAT must be text or json"),
        };
        Ok(Self { filter, format })
    }
}

pub fn init(config: &Config) {
    match config.format {
        Format::Json => tracing_subscriber::fmt()
            .with_env_filter(config.filter.clone())
            .json()
            .with_writer(std::io::stderr)
            .init(),
        Format::Text => tracing_subscriber::fmt()
            .with_env_filter(config.filter.clone())
            .with_writer(std::io::stderr)
            .init(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_agentio_log_options() {
        let config = Config::new("none", "json").unwrap();
        assert_eq!(config.filter.to_string(), "agentio_porter=off");
        assert!(matches!(config.format, Format::Json));
        assert!(Config::new("debug", "text").is_ok());
        assert!(Config::new("invalid", "text").is_err());
    }
}
