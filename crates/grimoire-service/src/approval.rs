//! Shared access approval logic used by both JSON-RPC sessions and the SSH agent.
//!
//! Approval flow: biometric → PIN → password (with server-side verification).
//! On PIN exhaustion, the vault auto-locks. On password entry, the password is
//! verified against the server — a prompt binary that returns a fake password
//! will not grant approval.

use grimoire_common::config::{PromptMethod, APPROVAL_SECONDS, PIN_MAX_ATTEMPTS};

use crate::prompt;
use crate::session::resolve_scope_key;
use crate::state::SharedState;

/// Attempt to obtain access approval via interactive prompt.
///
/// Tries biometric first, then PIN (if set), then master password (verified
/// against the server). Returns `true` only if the user was positively
/// authenticated. Grants approval in the cache on success.
///
/// On PIN exhaustion, auto-locks the vault and returns `false`.
pub async fn attempt_approval(
    state: &SharedState,
    prompt_method: &PromptMethod,
    peer_pid: Option<u32>,
) -> bool {
    // Check PIN exhaustion — too many failures → auto-lock
    {
        let s = state.read().await;
        if s.pin_attempts_exceeded() {
            tracing::info!("PIN attempts exceeded, locking vault");
            drop(s);
            let mut s = state.write().await;
            let _ = s.lock().await;
            return false;
        }
    }

    // Try biometric first
    if *prompt_method != PromptMethod::Terminal {
        match prompt::prompt_biometric(prompt_method, "Grimoire: approve vault access").await {
            Ok(true) => {
                grant_approval(state, peer_pid).await;
                return true;
            }
            Ok(false) => {} // Cancelled or unavailable, fall through
            Err(e) => {
                tracing::debug!("Biometric unavailable: {e}");
            }
        }
    }

    // Try PIN if set
    let has_pin = state.read().await.pin_set();
    if has_pin {
        let attempt = {
            let s = state.read().await;
            s.session.as_ref().map(|s| s.pin_attempts + 1).unwrap_or(1)
        };
        match prompt::prompt_pin(prompt_method, attempt, PIN_MAX_ATTEMPTS).await {
            Ok(Some(pin)) => {
                let mut s = state.write().await;
                if s.verify_pin(&pin) {
                    drop(s);
                    grant_approval(state, peer_pid).await;
                    return true;
                }
                // PIN failed — check if now exceeded
                if s.pin_attempts_exceeded() {
                    tracing::info!("PIN attempts exceeded after failure, locking vault");
                    let _ = s.lock().await;
                }
                return false;
            }
            _ => return false, // Cancelled
        }
    }

    // No biometric, no PIN — fall back to password prompt (GUI dialog).
    // The returned password MUST be verified against the server to prevent
    // a malicious prompt binary from granting approval with a fake password.
    match prompt::prompt_password(prompt_method).await {
        Ok(Some(password)) => {
            let verified = {
                let s = state.read().await;
                s.verify_password(&password).await
            };
            match verified {
                Ok(()) => {
                    grant_approval(state, peer_pid).await;
                    true
                }
                Err(e) => {
                    tracing::warn!("Password prompt verification failed: {e}");
                    false
                }
            }
        }
        _ => false,
    }
}

/// Record an approval grant in the cache for the resolved scope key.
async fn grant_approval(state: &SharedState, peer_pid: Option<u32>) {
    let scope_key = resolve_scope_key(peer_pid);
    let duration = std::time::Duration::from_secs(APPROVAL_SECONDS);
    state
        .write()
        .await
        .approval_cache
        .grant(scope_key, duration);
    tracing::info!(scope_key, "Access approved");
}
