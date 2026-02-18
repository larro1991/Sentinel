use sentinel::vuln::cors::CorsCheck;
use sentinel::vuln::dns_zone_transfer::DnsZoneTransferCheck;
use sentinel::vuln::smtp_relay::SmtpRelayCheck;
use sentinel::vuln::tls_ciphers::TlsCipherCheck;
use sentinel::vuln::{Service, VulnCheck};

fn http_service() -> Service {
    Service {
        host: "example.com".to_string(),
        port: 80,
        service_name: "http".to_string(),
        version: None,
        banner: None,
        tls: false,
    }
}

fn dns_service() -> Service {
    Service {
        host: "ns1.example.com".to_string(),
        port: 53,
        service_name: "dns".to_string(),
        version: None,
        banner: None,
        tls: false,
    }
}

fn smtp_service() -> Service {
    Service {
        host: "mail.example.com".to_string(),
        port: 25,
        service_name: "smtp".to_string(),
        version: None,
        banner: None,
        tls: false,
    }
}

fn tls_service() -> Service {
    Service {
        host: "example.com".to_string(),
        port: 443,
        service_name: "https".to_string(),
        version: None,
        banner: None,
        tls: true,
    }
}

fn ssh_service() -> Service {
    Service {
        host: "example.com".to_string(),
        port: 22,
        service_name: "ssh".to_string(),
        version: None,
        banner: None,
        tls: false,
    }
}

// ── CORS Check ───────────────────────────────────────────────────────────────

#[test]
fn test_cors_applies_to_http() {
    let check = CorsCheck::new();
    assert!(check.applies_to(&http_service()));
    assert!(!check.applies_to(&ssh_service()));
    assert!(!check.applies_to(&dns_service()));
}

#[test]
fn test_cors_name_and_metadata() {
    let check = CorsCheck::new();
    assert_eq!(check.name(), "cors-check");
    assert!(check.is_safe());
}

// ── DNS Zone Transfer Check ──────────────────────────────────────────────────

#[test]
fn test_dns_zone_applies_to_dns() {
    let check = DnsZoneTransferCheck::new();
    assert!(check.applies_to(&dns_service()));
    assert!(!check.applies_to(&http_service()));
    assert!(!check.applies_to(&ssh_service()));
}

#[test]
fn test_dns_zone_name_and_metadata() {
    let check = DnsZoneTransferCheck::new();
    assert_eq!(check.name(), "dns-zone-transfer-check");
    assert!(check.is_safe());
}

// ── SMTP Relay Check ─────────────────────────────────────────────────────────

#[test]
fn test_smtp_relay_applies_to_smtp() {
    let check = SmtpRelayCheck::new();
    assert!(check.applies_to(&smtp_service()));
    assert!(!check.applies_to(&http_service()));
    assert!(!check.applies_to(&dns_service()));
}

#[test]
fn test_smtp_relay_name_and_metadata() {
    let check = SmtpRelayCheck::new();
    assert_eq!(check.name(), "smtp-relay-check");
    assert!(check.is_safe());
}

// ── TLS Cipher Check ─────────────────────────────────────────────────────────

#[test]
fn test_tls_cipher_applies_to_tls() {
    let check = TlsCipherCheck::new();
    assert!(check.applies_to(&tls_service()));
    assert!(!check.applies_to(&ssh_service()));
    // Port 443 should match even if service_name doesn't say http.
    let port_443 = Service {
        host: "example.com".to_string(),
        port: 443,
        service_name: "unknown".to_string(),
        version: None,
        banner: None,
        tls: false,
    };
    assert!(check.applies_to(&port_443));
}

#[test]
fn test_tls_cipher_name_and_metadata() {
    let check = TlsCipherCheck::new();
    assert_eq!(check.name(), "tls-cipher-check");
    assert!(check.is_safe());
}

// ── Verify all 4 checks register in default_checks ──────────────────────────

#[test]
fn test_new_checks_registered_in_defaults() {
    let checks = sentinel::vuln::default_checks();
    let names: Vec<&str> = checks.iter().map(|c| c.name()).collect();
    assert!(names.contains(&"cors-check"), "cors-check missing from defaults");
    assert!(
        names.contains(&"dns-zone-transfer-check"),
        "dns-zone-transfer-check missing from defaults"
    );
    assert!(
        names.contains(&"smtp-relay-check"),
        "smtp-relay-check missing from defaults"
    );
    assert!(
        names.contains(&"tls-cipher-check"),
        "tls-cipher-check missing from defaults"
    );
    // Should have 11 total checks now (7 original + 4 new).
    assert_eq!(checks.len(), 11);
}
