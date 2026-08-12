#![no_main]

use std::collections::{BTreeMap, BTreeSet};

use cartridge_network::{HttpMethod, HttpPolicy, HttpRequest, HttpScope};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(url) = std::str::from_utf8(data) else { return; };
    let policy = HttpPolicy {
        scopes: vec![HttpScope {
            scheme: "https".into(),
            host: "example.com".into(),
            port: None,
            path_prefix: "/api".into(),
            methods: BTreeSet::from([HttpMethod::Get]),
        }],
        ..HttpPolicy::default()
    };
    let _ = policy.authorize(&HttpRequest {
        method: HttpMethod::Get,
        url: url.into(),
        headers: BTreeMap::new(),
        body: Vec::new(),
    });
});
