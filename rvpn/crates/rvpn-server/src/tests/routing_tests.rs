//! Routing tests - testing China vs external traffic routing

use std::net::IpAddr;
use std::str::FromStr;

use rvpn_core::routing::{RoutingEngine, RouteAction};

/// Test IP classification
#[tokio::test]
async fn test_ip_classification() -> anyhow::Result<()> {
    let mut engine = RoutingEngine::new();
    engine.add_china_ip("220.0.0.0/8")?;

    // Test China IP
    let china_ip = IpAddr::from_str("220.181.38.148")?;
    assert_eq!(engine.route_ip(china_ip), RouteAction::Direct, "Expected China IP to route direct");

    // Test US IP
    let us_ip = IpAddr::from_str("142.250.185.78")?;
    assert_eq!(engine.route_ip(us_ip), RouteAction::Proxy, "Expected US IP to route via proxy");

    Ok(())
}

/// Test domain classification
#[tokio::test]
async fn test_domain_classification() -> anyhow::Result<()> {
    let mut engine = RoutingEngine::new();
    engine.add_china_domain(".cn");

    // Test China domain
    assert_eq!(engine.route_domain("baidu.com.cn"), RouteAction::Direct, "China domain should be direct");

    // Test US domain
    assert_eq!(engine.route_domain("google.com"), RouteAction::Proxy, "US domain should be proxy");

    Ok(())
}

/// Test default routing
#[tokio::test]
async fn test_default_routing() -> anyhow::Result<()> {
    let engine = RoutingEngine::new();

    // Default should be proxy
    let ip: IpAddr = "8.8.8.8".parse()?;
    assert_eq!(engine.route_ip(ip), RouteAction::Proxy);

    Ok(())
}

/// Test blocked domains
#[tokio::test]
async fn test_blocked_domains() -> anyhow::Result<()> {
    let mut engine = RoutingEngine::new();
    engine.add_blocked_domain("malware.example");

    assert_eq!(engine.route_domain("malware.example"), RouteAction::Block);

    Ok(())
}

/// Test route decision with domain and IP
#[tokio::test]
async fn test_combined_routing() -> anyhow::Result<()> {
    let mut engine = RoutingEngine::new();
    let _ = engine.add_china_ip("220.0.0.0/8");
    let _ = engine.add_china_domain(".cn");

    // Domain match should take precedence
    // google.com.cn should be direct (matches .cn)
    let result = engine.route(Some("8.8.8.8".parse()?), Some("google.com.cn"));
    assert_eq!(result, RouteAction::Direct, "China domain should route direct");

    // google.com should be proxy
    let result = engine.route(Some("8.8.8.8".parse()?), Some("google.com"));
    assert_eq!(result, RouteAction::Proxy, "Non-China domain should route proxy");

    Ok(())
}
