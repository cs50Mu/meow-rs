use std::path::PathBuf;
use std::sync::OnceLock;

static HOME_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Override the default home directory (normally `$XDG_CONFIG_HOME/meow`
/// or `$HOME/.config/meow`). Call once at startup from CLI arg parsing.
pub fn set_home_dir(dir: PathBuf) {
    let _ = HOME_DIR.set(dir);
}

/// Returns the configured home directory, or falls back to the XDG/HOME-based
/// default via [`default_config_dir`].
pub fn home_dir() -> PathBuf {
    HOME_DIR.get().cloned().unwrap_or_else(default_config_dir)
}

/// Default config directory: `$XDG_CONFIG_HOME/meow` or `$HOME/.config/meow`.
pub fn default_config_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("meow")
}
