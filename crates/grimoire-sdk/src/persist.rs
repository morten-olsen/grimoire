//! Persistent login state — survives service restarts.
//!
//! After a successful login, we save email + server_url to disk so
//! the user only needs `grimoire unlock` (master password) on next startup.
//! The master password is never stored — unlock re-authenticates with the server.

use crate::auth::LoginState;
use crate::error::SdkError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
struct PersistedLogin {
    email: String,
    server_url: String,
}

fn state_file_path() -> Option<PathBuf> {
    dirs::data_dir().map(|d| d.join("grimoire").join("login.json"))
}

/// Save login state to disk after successful login.
pub fn save_login_state(state: &LoginState) -> Result<(), SdkError> {
    let path = state_file_path()
        .ok_or_else(|| SdkError::Internal("Cannot determine data directory".into()))?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| SdkError::Internal(format!("Failed to create data dir: {e}")))?;
    }

    let persisted = PersistedLogin {
        email: state.email.clone(),
        server_url: state.server_url.clone(),
    };

    let json = serde_json::to_string_pretty(&persisted)
        .map_err(|e| SdkError::Internal(format!("Failed to serialize: {e}")))?;

    // Create file with 0600 permissions atomically — no TOCTOU window.
    // fsync to ensure data reaches disk before we report success.
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut f| {
            f.write_all(json.as_bytes())?;
            f.sync_all()
        })
        .map_err(|e| SdkError::Internal(format!("Failed to write {}: {e}", path.display())))?;

    tracing::info!("Login state saved to {}", path.display());
    Ok(())
}

/// Load persisted login state from disk. Returns None if no saved state exists.
pub fn load_login_state() -> Result<Option<LoginState>, SdkError> {
    let path = match state_file_path() {
        Some(p) if p.exists() => p,
        _ => return Ok(None),
    };

    let json = fs::read_to_string(&path)
        .map_err(|e| SdkError::Internal(format!("Failed to read {}: {e}", path.display())))?;

    let persisted: PersistedLogin = serde_json::from_str(&json)
        .map_err(|e| SdkError::Internal(format!("Failed to parse login state: {e}")))?;

    Ok(Some(LoginState {
        email: persisted.email,
        server_url: persisted.server_url,
    }))
}

// --- Backoff persistence ---
// Prevents attackers from bypassing rate limiting by restarting the service.

#[derive(Serialize, Deserialize, Default)]
struct PersistedBackoff {
    attempts: u32,
    /// Unix timestamp (seconds) of the last failed attempt.
    last_attempt_epoch: Option<u64>,
}

fn backoff_file_path() -> Option<PathBuf> {
    dirs::data_dir().map(|d| d.join("grimoire").join("backoff.json"))
}

/// Load persisted backoff state. Returns (attempts, last_attempt_epoch).
/// Returns defaults if the file doesn't exist or can't be parsed.
pub fn load_backoff() -> (u32, Option<u64>) {
    let Some(path) = backoff_file_path() else {
        return (0, None);
    };
    let Ok(json) = fs::read_to_string(&path) else {
        return (0, None);
    };
    let Ok(state) = serde_json::from_str::<PersistedBackoff>(&json) else {
        return (0, None);
    };
    (state.attempts, state.last_attempt_epoch)
}

/// Save backoff state to disk after a failed password attempt.
pub fn save_backoff(attempts: u32, last_attempt_epoch: Option<u64>) {
    let Some(path) = backoff_file_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let state = PersistedBackoff {
        attempts,
        last_attempt_epoch,
    };
    let Ok(json) = serde_json::to_string(&state) else {
        return;
    };
    let _ = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut f| f.write_all(json.as_bytes()));
}

/// Clear backoff state (on successful authentication).
pub fn clear_backoff() {
    if let Some(path) = backoff_file_path() {
        let _ = fs::remove_file(&path);
    }
}

/// Delete persisted login state (on logout).
pub fn clear_login_state() {
    if let Some(path) = state_file_path() {
        if path.exists() {
            if let Err(e) = fs::remove_file(&path) {
                tracing::warn!("Failed to remove {}: {e}", path.display());
            } else {
                tracing::info!("Login state cleared");
            }
        }
    }
}
