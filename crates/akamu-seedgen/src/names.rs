//! Deterministic fake name generation for seeded test data.

use rand::Rng;

/// Fake zone labels — kept short so domain names stay under 253 chars.
static ZONES: &[&str] = &[
    "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet",
];

static ADJECTIVES: &[&str] = &[
    "red", "blue", "green", "fast", "slow", "big", "small", "bright", "dark", "loud", "quiet",
    "old", "new",
];

static NOUNS: &[&str] = &[
    "server", "host", "node", "proxy", "gateway", "edge", "backend", "frontend", "api", "web",
];

/// Generate a fake DNS hostname like `fast-server-42.echo.acme-test.localhost`.
///
/// Uses `.localhost` as the TLD so that names resolve to the loopback address
/// (127.0.0.1) via RFC 6761 / systemd-resolved, allowing http-01 challenge
/// validation to reach the in-process challenge responder.
pub fn next_domain(rng: &mut impl Rng, scenario_name: &str) -> String {
    let adj = ADJECTIVES[rng.gen_range(0..ADJECTIVES.len())];
    let noun = NOUNS[rng.gen_range(0..NOUNS.len())];
    let zone = ZONES[rng.gen_range(0..ZONES.len())];
    let n: u32 = rng.gen_range(1..10000);
    format!("{adj}-{noun}-{n}.{zone}.{scenario_name}.localhost")
}

/// Generate N distinct fake hostnames for a multi-SAN cert.
pub fn next_domains(rng: &mut impl Rng, scenario_name: &str, n: usize) -> Vec<String> {
    let mut domains = Vec::with_capacity(n);
    let base = next_domain(rng, scenario_name);
    domains.push(base.clone());
    // Additional SANs: prepend sub-labels to the base.
    for i in 1..n {
        let prefix = ADJECTIVES[rng.gen_range(0..ADJECTIVES.len())];
        // Extract the zone+tld suffix after the first dot.
        let suffix = base
            .split_once('.')
            .map(|x| x.1)
            .unwrap_or("acme-test.example");
        domains.push(format!("{prefix}-sub{i}.{suffix}"));
    }
    domains
}

/// Generate a fake email contact URI.
pub fn next_contact(rng: &mut impl Rng) -> String {
    let adj = ADJECTIVES[rng.gen_range(0..ADJECTIVES.len())];
    let noun = NOUNS[rng.gen_range(0..NOUNS.len())];
    let n: u32 = rng.gen_range(1..10000);
    format!("mailto:{adj}.{noun}.{n}@acme-test.localhost")
}

/// Pick a key type from a weight map using weighted random selection.
///
/// Keys are sorted before selection so that the same RNG seed always produces
/// the same output regardless of `HashMap` insertion order.
/// Returns `"ec:P-256"` if the map is empty or all weights are zero.
pub fn pick_key_type(
    rng: &mut impl Rng,
    weights: &std::collections::HashMap<String, u32>,
) -> String {
    if weights.is_empty() {
        return "ec:P-256".to_string();
    }
    let total: u32 = weights.values().sum();
    if total == 0 {
        let mut keys: Vec<&String> = weights.keys().collect();
        keys.sort();
        return keys
            .first()
            .copied()
            .cloned()
            .unwrap_or_else(|| "ec:P-256".to_string());
    }
    // Sort keys for deterministic iteration order.
    let mut sorted: Vec<(&String, &u32)> = weights.iter().collect();
    sorted.sort_by_key(|(k, _)| k.as_str());

    let mut pick = rng.gen_range(0..total);
    for (kt, w) in &sorted {
        if pick < **w {
            return (*kt).clone();
        }
        pick -= *w;
    }
    sorted
        .last()
        .map(|(k, _)| (*k).clone())
        .unwrap_or_else(|| "ec:P-256".to_string())
}
