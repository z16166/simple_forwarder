use ipnet::IpNet;
use std::net::IpAddr;
use wildmatch::WildMatch;

#[derive(Clone)]
pub struct RuleMatcher {
    patterns: Vec<Pattern>,
}

#[derive(Clone)]
enum Pattern {
    Domain(WildMatch),
    Ip(IpAddr),
    Cidr(IpNet),
}

impl RuleMatcher {
    pub fn new(patterns: Vec<String>) -> Self {
        let parsed_patterns = patterns.into_iter()
            .filter_map(|p| Self::parse_pattern(p))
            .collect();

        Self { patterns: parsed_patterns }
    }

    fn parse_pattern(pattern: String) -> Option<Pattern> {
        if pattern.contains('/') {
            pattern.parse::<IpNet>().ok().map(Pattern::Cidr)
        } else if pattern.parse::<IpAddr>().is_ok() {
            pattern.parse::<IpAddr>().ok().map(Pattern::Ip)
        } else {
            Some(Pattern::Domain(WildMatch::new(&pattern)))
        }
    }

    pub fn matches(&self, host: &str, ip: Option<IpAddr>) -> bool {
        for pattern in &self.patterns {
            if self.match_pattern(pattern, host, ip) {
                return true;
            }
        }
        false
    }

    fn match_pattern(&self, pattern: &Pattern, host: &str, ip: Option<IpAddr>) -> bool {
        match pattern {
            Pattern::Domain(matcher) => {
                matcher.matches(host)
            }
            Pattern::Ip(pattern_ip) => {
                if let Some(ip) = ip {
                    ip == *pattern_ip
                } else {
                    false
                }
            }
            Pattern::Cidr(cidr) => {
                if let Some(ip) = ip {
                    cidr.contains(&ip)
                } else {
                    false
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_wildcard() {
        let matcher = RuleMatcher::new(vec![
            "*.google.com".to_string(),
        ]);

        assert!(matcher.matches("www.google.com", None));
        assert!(matcher.matches("mail.google.com", None));
        assert!(!matcher.matches("google.com", None));
        assert!(!matcher.matches("example.com", None));
    }

    #[test]
    fn test_ip_match() {
        let ip = "192.168.1.1".parse().unwrap();
        let matcher = RuleMatcher::new(vec![
            "192.168.1.1".to_string(),
        ]);

        assert!(matcher.matches("example.com", Some(ip)));
        assert!(!matcher.matches("example.com", Some("192.168.1.2".parse().unwrap())));
    }

    #[test]
    fn test_cidr_match() {
        let matcher = RuleMatcher::new(vec![
            "192.168.1.0/24".to_string(),
        ]);

        assert!(matcher.matches("example.com", Some("192.168.1.1".parse().unwrap())));
        assert!(matcher.matches("example.com", Some("192.168.1.255".parse().unwrap())));
        assert!(!matcher.matches("example.com", Some("192.168.2.1".parse().unwrap())));
    }

    #[test]
    fn test_ipv6_cidr() {
        let matcher = RuleMatcher::new(vec![
            "2001:db8::/32".to_string(),
        ]);

        assert!(matcher.matches("example.com", Some("2001:db8::1".parse().unwrap())));
        assert!(!matcher.matches("example.com", Some("2001:db9::1".parse().unwrap())));
    }

    #[test]
    fn test_mixed_patterns() {
        let matcher = RuleMatcher::new(vec![
            "*.google.com".to_string(),
            "192.168.1.0/24".to_string(),
            "10.0.0.1".to_string(),
        ]);

        assert!(matcher.matches("www.google.com", None));
        assert!(matcher.matches("example.com", Some("192.168.1.1".parse().unwrap())));
        assert!(matcher.matches("example.com", Some("10.0.0.1".parse().unwrap())));
        assert!(!matcher.matches("example.com", Some("10.0.0.2".parse().unwrap())));
    }
}
