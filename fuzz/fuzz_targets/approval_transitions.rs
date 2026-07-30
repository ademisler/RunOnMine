#![no_main]

use chrono::{Duration, Utc};
use libfuzzer_sys::fuzz_target;
use runonmine_core::{
    ApprovalDecision, ApprovalPrincipal, ApprovalRequest, ApprovalStatus, StateStore,
};

fuzz_target!(|data: &[u8]| {
    if data.len() > 512 {
        return;
    }
    let Ok(store) = StateStore::in_memory() else {
        return;
    };
    let principal = match data.first().copied().unwrap_or_default() % 4 {
        0 => ApprovalPrincipal::LocalStdio,
        1 => ApprovalPrincipal::LocalHttp,
        2 => ApprovalPrincipal::QuickTunnel,
        _ => ApprovalPrincipal::OAuth {
            client_id: "fuzz-client".to_owned(),
            subject: "fuzz-owner".to_owned(),
        },
    };
    let request = ApprovalRequest::new(
        "fuzz-connector",
        principal.clone(),
        "fs_write",
        "write fuzz target",
        "fuzz-argument-hash",
        Utc::now() + Duration::hours(1),
    );
    if store.insert_approval(&request).is_err() {
        return;
    }

    let mut expected_status = ApprovalStatus::Pending;
    let mut expected_decision = None;
    let mut grant_active = false;
    for operation in data.iter().copied().skip(1) {
        match operation % 8 {
            0..=3 => {
                let decision = match operation % 4 {
                    0 => ApprovalDecision::Once,
                    1 => ApprovalDecision::ForTenMinutes,
                    2 => ApprovalDecision::Always,
                    _ => ApprovalDecision::Deny,
                };
                let resolved = store.resolve_approval(request.id, decision).unwrap_or(false);
                let expected_resolved = expected_status == ApprovalStatus::Pending;
                assert_eq!(resolved, expected_resolved);
                if resolved {
                    expected_status = if decision == ApprovalDecision::Deny {
                        ApprovalStatus::Denied
                    } else {
                        ApprovalStatus::Approved
                    };
                    expected_decision = Some(decision);
                    grant_active = matches!(
                        decision,
                        ApprovalDecision::ForTenMinutes | ApprovalDecision::Always
                    );
                }
            }
            4 => {
                let stored = store
                    .approval_status(request.id)
                    .expect("approval status query failed")
                    .expect("approval disappeared");
                assert_eq!(stored.status, expected_status);
                assert_eq!(stored.decision, expected_decision);
                assert_eq!(stored.principal_fingerprint, principal.fingerprint());
            }
            5 => {
                let pending = store.pending_approvals().expect("pending query failed");
                assert_eq!(pending.iter().any(|item| item.id == request.id), expected_status == ApprovalStatus::Pending);
            }
            6 => {
                let allowed = store
                    .grant_allows(
                        "fuzz-connector",
                        &principal,
                        "fs_write",
                        "fuzz-argument-hash",
                    )
                    .expect("grant query failed");
                assert_eq!(allowed, grant_active);
            }
            _ => {
                let _cleared = store
                    .clear_persistent_grants(Some("fuzz-connector"))
                    .expect("persistent grant cleanup failed");
                if expected_decision == Some(ApprovalDecision::Always) {
                    grant_active = false;
                }
            }
        }
    }
});
