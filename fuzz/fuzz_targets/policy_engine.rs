#![no_main]

use libfuzzer_sys::fuzz_target;
use runonmine_core::{
    Capability, ConnectorConfig, PolicyContext, PolicyEngine, PolicyRule, PrincipalContext,
    ResourceContext,
};
use url::Url;

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }
    let mut connector = ConnectorConfig::local_default();
    if let Ok(rule) = serde_json::from_slice::<PolicyRule>(data) {
        connector.policy_rules.push(rule);
    }
    let text = String::from_utf8_lossy(data);
    let url = Url::parse("https://example.com/").ok();
    for capability in Capability::ALL {
        let contexts = [
            PolicyContext {
                principal: PrincipalContext::Local,
                resource: ResourceContext::Command(&text),
            },
            PolicyContext {
                principal: PrincipalContext::Local,
                resource: ResourceContext::Filesystem(std::path::Path::new(text.as_ref())),
            },
        ];
        for context in &contexts {
            let _ = PolicyEngine.evaluate_context(&connector, &text, capability, context);
        }
        if let Some(url) = &url {
            let context = PolicyContext {
                principal: PrincipalContext::OAuth {
                    client_id: &text,
                    subject: &text,
                },
                resource: ResourceContext::Browser(url),
            };
            let _ = PolicyEngine.evaluate_context(&connector, &text, capability, &context);
        }
    }
});
