#![allow(clippy::expect_used)]

use std::process::Command;

fn run_offline() -> Vec<u8> {
    let output = Command::new(env!("CARGO_BIN_EXE_accordlock"))
        .args(["offline", "--compact"])
        .output()
        .expect("offline demo process must start");
    assert!(
        output.status.success(),
        "offline demo failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    output.stdout
}

#[test]
fn one_command_offline_report_is_deterministic_and_honest() {
    let first = run_offline();
    let second = run_offline();
    assert_eq!(first, second);

    let report: serde_json::Value =
        serde_json::from_slice(&first).expect("offline report must be valid JSON");
    assert_eq!(report["schema_version"], 2);
    assert_eq!(report["production_ready"], false);
    assert_eq!(report["benchmark"], false);
    assert_eq!(
        report["execution_profile"]["determinism"],
        "FIXED_FIXTURES_AND_OUTPUT"
    );
    assert_eq!(
        report["execution_profile"]["network_access"],
        "NOT_ACCESSED"
    );
    assert_eq!(report["execution_profile"]["external_mutation"], "NONE");
    assert_eq!(
        report["execution_profile"]["credential_source"],
        "PUBLIC_HARD_CODED_TEST_KEYS_ONLY"
    );
    assert_eq!(
        report["execution_profile"]["production_enforcement_entry_point"],
        "NOT_INVOKED"
    );

    let scenarios = report["scenarios"]
        .as_array()
        .expect("scenarios must be an array");
    let scenario = |id: &str| {
        scenarios
            .iter()
            .find(|candidate| candidate["scenario_id"] == id)
            .expect("required scenario must be present")
    };
    assert_eq!(
        scenario("DP-000")["accordlock"]["final_effect_authorized"],
        true
    );
    assert_eq!(
        scenario("DP-000")["accordlock"]["replay_attempt"]["reason"],
        "ALREADY_CONSUMED"
    );
    assert_eq!(
        scenario("DP-101")["accordlock"]["final_effect_authorized"],
        false
    );
    assert_eq!(
        scenario("DP-103")["accordlock"]["post_admission_projection"]["reason"],
        "UNAUTHORIZED_POST_ADMISSION_DELTA"
    );

    let gates = report["coverage"]["live_gates"]
        .as_array()
        .expect("live gates must be an array");
    assert_eq!(gates.len(), 3);
    assert!(gates.iter().all(|gate| gate["satisfied"] == false));
}
