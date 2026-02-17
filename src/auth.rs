use std::fmt;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// Authorization levels for security assessment operations, ordered from least to most invasive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationLevel {
    Passive,
    Scanning,
    Verification,
    Exploitation,
    PostExploit,
}

impl AuthorizationLevel {
    fn ordinal(&self) -> u8 {
        match self {
            AuthorizationLevel::Passive => 0,
            AuthorizationLevel::Scanning => 1,
            AuthorizationLevel::Verification => 2,
            AuthorizationLevel::Exploitation => 3,
            AuthorizationLevel::PostExploit => 4,
        }
    }

    /// Parse from a string representation (case-insensitive).
    pub fn from_str_loose(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "passive" => Ok(AuthorizationLevel::Passive),
            "scanning" => Ok(AuthorizationLevel::Scanning),
            "verification" => Ok(AuthorizationLevel::Verification),
            "exploitation" => Ok(AuthorizationLevel::Exploitation),
            "post_exploit" | "postexploit" | "post-exploit" => Ok(AuthorizationLevel::PostExploit),
            other => bail!("Unknown authorization level: '{}'", other),
        }
    }
}

impl PartialOrd for AuthorizationLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AuthorizationLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.ordinal().cmp(&other.ordinal())
    }
}

impl fmt::Display for AuthorizationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthorizationLevel::Passive => write!(f, "Passive"),
            AuthorizationLevel::Scanning => write!(f, "Scanning"),
            AuthorizationLevel::Verification => write!(f, "Verification"),
            AuthorizationLevel::Exploitation => write!(f, "Exploitation"),
            AuthorizationLevel::PostExploit => write!(f, "Post-Exploit"),
        }
    }
}

/// Manages authorization level enforcement for an engagement.
#[derive(Debug, Clone)]
pub struct AuthorizationManager {
    pub max_level: AuthorizationLevel,
    pub auto_approve_up_to: AuthorizationLevel,
}

impl AuthorizationManager {
    pub fn new(max_level: AuthorizationLevel, auto_approve_up_to: AuthorizationLevel) -> Self {
        Self {
            max_level,
            auto_approve_up_to,
        }
    }

    /// Check whether the required authorization level is permitted.
    /// Returns an error if the required level exceeds the maximum authorized level.
    pub fn check(&self, required: AuthorizationLevel) -> Result<()> {
        if required > self.max_level {
            bail!(
                "Authorization denied: operation requires {} but max authorized level is {}",
                required,
                self.max_level
            );
        }
        Ok(())
    }
}
