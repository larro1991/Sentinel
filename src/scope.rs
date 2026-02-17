use std::net::IpAddr;

use chrono::{Datelike, NaiveTime, Timelike, Utc, Weekday};
use ipnet::IpNet;
use thiserror::Error;

use crate::auth::AuthorizationLevel;
use crate::config::{AuthorizationConfig, ScopeConfig};

#[derive(Debug, Error)]
pub enum ScopeError {
    #[error("Target '{0}' is out of scope")]
    OutOfScope(String),

    #[error("Target '{0}' is in the exclusion list")]
    Excluded(String),

    #[error("Current time is outside the authorized time window")]
    OutsideTimeWindow,

    #[error("Insufficient authorization: requires {required}, max authorized is {max}")]
    InsufficientAuthorization {
        required: AuthorizationLevel,
        max: AuthorizationLevel,
    },

    #[error("Invalid target specification: '{0}'")]
    InvalidTarget(String),
}

/// A parsed time window with start/end times and optional day restrictions.
#[derive(Debug, Clone)]
struct ParsedTimeWindow {
    start: NaiveTime,
    end: NaiveTime,
    days: Option<Vec<Weekday>>,
}

impl ParsedTimeWindow {
    /// Check whether the given time and weekday fall within this window.
    /// Handles overnight windows where start > end (e.g. 22:00 -> 06:00).
    fn contains(&self, time: NaiveTime, weekday: Weekday) -> bool {
        // Check day restriction first.
        if let Some(ref days) = self.days {
            if !days.contains(&weekday) {
                return false;
            }
        }

        if self.start <= self.end {
            // Normal window: 09:00 -> 17:00
            time >= self.start && time <= self.end
        } else {
            // Overnight window: 22:00 -> 06:00
            time >= self.start || time <= self.end
        }
    }
}

/// Parse a day-of-week abbreviation to a chrono Weekday.
fn parse_weekday(s: &str) -> Option<Weekday> {
    match s.to_lowercase().as_str() {
        "mon" | "monday" => Some(Weekday::Mon),
        "tue" | "tuesday" => Some(Weekday::Tue),
        "wed" | "wednesday" => Some(Weekday::Wed),
        "thu" | "thursday" => Some(Weekday::Thu),
        "fri" | "friday" => Some(Weekday::Fri),
        "sat" | "saturday" => Some(Weekday::Sat),
        "sun" | "sunday" => Some(Weekday::Sun),
        _ => None,
    }
}

/// The core scope enforcement engine. Every network operation must pass through this
/// validator before execution.
#[derive(Debug)]
pub struct ScopeValidator {
    target_networks: Vec<IpNet>,
    target_hostnames: Vec<String>,
    exclusion_networks: Vec<IpNet>,
    exclusion_hostnames: Vec<String>,
    time_windows: Vec<ParsedTimeWindow>,
    max_authorization: AuthorizationLevel,
}

impl ScopeValidator {
    /// Build a ScopeValidator from the engagement configuration sections.
    pub fn new(scope: &ScopeConfig, auth: &AuthorizationConfig) -> Result<Self, ScopeError> {
        let mut target_networks = Vec::new();
        let mut target_hostnames = Vec::new();

        for target in &scope.targets {
            if let Ok(net) = target.parse::<IpNet>() {
                target_networks.push(net);
            } else if let Ok(addr) = target.parse::<IpAddr>() {
                // Single IP without prefix — wrap as /32 or /128
                let net = IpNet::from(addr);
                target_networks.push(net);
            } else {
                // Treat as a hostname (may include wildcards like *.example.com)
                target_hostnames.push(target.clone());
            }
        }

        let mut exclusion_networks = Vec::new();
        let mut exclusion_hostnames = Vec::new();

        for excl in &scope.exclusions {
            if let Ok(net) = excl.parse::<IpNet>() {
                exclusion_networks.push(net);
            } else if let Ok(addr) = excl.parse::<IpAddr>() {
                let net = IpNet::from(addr);
                exclusion_networks.push(net);
            } else {
                exclusion_hostnames.push(excl.clone());
            }
        }

        let mut time_windows = Vec::new();
        for tw in &scope.time_windows {
            let start = NaiveTime::parse_from_str(&tw.start, "%H:%M")
                .map_err(|_| ScopeError::InvalidTarget(format!("Invalid start time: {}", tw.start)))?;
            let end = NaiveTime::parse_from_str(&tw.end, "%H:%M")
                .map_err(|_| ScopeError::InvalidTarget(format!("Invalid end time: {}", tw.end)))?;

            let days = if let Some(ref day_strs) = tw.days {
                let mut parsed = Vec::new();
                for d in day_strs {
                    let wd = parse_weekday(d).ok_or_else(|| {
                        ScopeError::InvalidTarget(format!("Unknown day: {}", d))
                    })?;
                    parsed.push(wd);
                }
                Some(parsed)
            } else {
                None
            };

            time_windows.push(ParsedTimeWindow { start, end, days });
        }

        let max_authorization = AuthorizationLevel::from_str_loose(&auth.max_level)
            .map_err(|e| ScopeError::InvalidTarget(format!("Bad authorization level: {}", e)))?;

        Ok(Self {
            target_networks,
            target_hostnames,
            exclusion_networks,
            exclusion_hostnames,
            time_windows,
            max_authorization,
        })
    }

    /// Check whether an IP address is in scope (not excluded and within targets).
    pub fn validate_ip(&self, addr: &IpAddr) -> Result<(), ScopeError> {
        // Check exclusions first — exclusions always win.
        for net in &self.exclusion_networks {
            if net.contains(addr) {
                return Err(ScopeError::Excluded(addr.to_string()));
            }
        }

        // If there are no target networks, the engagement is hostname-only; skip IP check.
        if self.target_networks.is_empty() {
            return Ok(());
        }

        for net in &self.target_networks {
            if net.contains(addr) {
                return Ok(());
            }
        }

        Err(ScopeError::OutOfScope(addr.to_string()))
    }

    /// Check whether a hostname is in scope (not excluded and matches targets).
    /// Supports wildcards: "*.example.com" matches "sub.example.com".
    pub fn validate_hostname(&self, hostname: &str) -> Result<(), ScopeError> {
        let lower = hostname.to_lowercase();

        // Check exclusions first.
        for excl in &self.exclusion_hostnames {
            if hostname_matches(&lower, &excl.to_lowercase()) {
                return Err(ScopeError::Excluded(hostname.to_string()));
            }
        }

        // If there are no target hostnames, only IP-based targets exist; allow hostnames
        // that will be resolved and validated as IPs later.
        if self.target_hostnames.is_empty() {
            return Ok(());
        }

        for target in &self.target_hostnames {
            if hostname_matches(&lower, &target.to_lowercase()) {
                return Ok(());
            }
        }

        Err(ScopeError::OutOfScope(hostname.to_string()))
    }

    /// Check whether the current UTC time falls within at least one configured time window.
    /// If no time windows are configured, all times are permitted.
    pub fn validate_time(&self) -> Result<(), ScopeError> {
        if self.time_windows.is_empty() {
            return Ok(());
        }

        let now = Utc::now();
        let time = NaiveTime::from_hms_opt(now.hour(), now.minute(), now.second())
            .unwrap_or_default();
        let weekday = now.weekday();

        for window in &self.time_windows {
            if window.contains(time, weekday) {
                return Ok(());
            }
        }

        Err(ScopeError::OutsideTimeWindow)
    }

    /// Check whether the required authorization level is permitted by this engagement.
    pub fn validate_authorization(&self, required: AuthorizationLevel) -> Result<(), ScopeError> {
        if required > self.max_authorization {
            return Err(ScopeError::InsufficientAuthorization {
                required,
                max: self.max_authorization,
            });
        }
        Ok(())
    }

    /// Validate all dimensions: target scope, time window, and authorization level.
    /// The target is first tried as an IP address; if that fails it is treated as a hostname.
    pub fn validate_all(&self, target: &str, required: AuthorizationLevel) -> Result<(), ScopeError> {
        // Validate time window.
        self.validate_time()?;

        // Validate authorization level.
        self.validate_authorization(required)?;

        // Validate target — try IP first, fall back to hostname.
        if let Ok(addr) = target.parse::<IpAddr>() {
            self.validate_ip(&addr)?;
        } else {
            // Could be "host:port" — strip port if present.
            let hostname = if let Some(colon_pos) = target.rfind(':') {
                let maybe_port = &target[colon_pos + 1..];
                if maybe_port.parse::<u16>().is_ok() {
                    &target[..colon_pos]
                } else {
                    target
                }
            } else {
                target
            };

            // Try again as IP after stripping port.
            if let Ok(addr) = hostname.parse::<IpAddr>() {
                self.validate_ip(&addr)?;
            } else {
                self.validate_hostname(hostname)?;
            }
        }

        Ok(())
    }

    /// Get the maximum authorization level for this engagement.
    pub fn max_authorization(&self) -> AuthorizationLevel {
        self.max_authorization
    }
}

/// Match a hostname against a pattern that may contain a leading wildcard.
/// e.g. "*.example.com" matches "sub.example.com" and "a.b.example.com".
fn hostname_matches(hostname: &str, pattern: &str) -> bool {
    if pattern.starts_with("*.") {
        let suffix = &pattern[1..]; // ".example.com"
        hostname.ends_with(suffix) || hostname == &pattern[2..]
    } else {
        hostname == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthorizationConfig, ScopeConfig, TimeWindowConfig};

    fn make_scope(targets: Vec<&str>, exclusions: Vec<&str>) -> ScopeConfig {
        ScopeConfig {
            targets: targets.into_iter().map(String::from).collect(),
            exclusions: exclusions.into_iter().map(String::from).collect(),
            time_windows: vec![],
        }
    }

    fn make_auth(level: &str) -> AuthorizationConfig {
        AuthorizationConfig {
            max_level: level.to_string(),
            auto_approve_up_to: None,
        }
    }

    #[test]
    fn test_ip_in_scope() {
        let scope = make_scope(vec!["10.0.0.0/24"], vec![]);
        let auth = make_auth("scanning");
        let v = ScopeValidator::new(&scope, &auth).unwrap();
        assert!(v.validate_ip(&"10.0.0.1".parse().unwrap()).is_ok());
        assert!(v.validate_ip(&"10.0.1.1".parse().unwrap()).is_err());
    }

    #[test]
    fn test_exclusion_wins() {
        let scope = make_scope(vec!["10.0.0.0/24"], vec!["10.0.0.5"]);
        let auth = make_auth("scanning");
        let v = ScopeValidator::new(&scope, &auth).unwrap();
        assert!(v.validate_ip(&"10.0.0.1".parse().unwrap()).is_ok());
        let err = v.validate_ip(&"10.0.0.5".parse().unwrap()).unwrap_err();
        assert!(matches!(err, ScopeError::Excluded(_)));
    }

    #[test]
    fn test_hostname_wildcard() {
        let scope = make_scope(vec!["*.example.com"], vec![]);
        let auth = make_auth("scanning");
        let v = ScopeValidator::new(&scope, &auth).unwrap();
        assert!(v.validate_hostname("sub.example.com").is_ok());
        assert!(v.validate_hostname("example.com").is_ok());
        assert!(v.validate_hostname("other.com").is_err());
    }

    #[test]
    fn test_authorization_check() {
        let scope = make_scope(vec!["10.0.0.0/8"], vec![]);
        let auth = make_auth("scanning");
        let v = ScopeValidator::new(&scope, &auth).unwrap();
        assert!(v.validate_authorization(AuthorizationLevel::Passive).is_ok());
        assert!(v.validate_authorization(AuthorizationLevel::Scanning).is_ok());
        assert!(v.validate_authorization(AuthorizationLevel::Verification).is_err());
    }

    #[test]
    fn test_time_window() {
        let scope = ScopeConfig {
            targets: vec!["10.0.0.0/8".to_string()],
            exclusions: vec![],
            time_windows: vec![TimeWindowConfig {
                start: "00:00".to_string(),
                end: "23:59".to_string(),
                days: None,
                timezone: None,
            }],
        };
        let auth = make_auth("scanning");
        let v = ScopeValidator::new(&scope, &auth).unwrap();
        // This window covers the whole day, so it should always pass.
        assert!(v.validate_time().is_ok());
    }
}
