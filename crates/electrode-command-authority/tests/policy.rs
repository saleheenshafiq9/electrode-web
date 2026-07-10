use electrode_command_authority::{
    CommandAuthorityConfig, CommandPolicy, Delivery, PolicyConfig, CANONICAL_FIRMWARE_QUERY_KEYS,
};
use flatbuffers::FlatBufferBuilder;
use sha2::{Digest, Sha256};
use std::fs;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use synapse_fbs::cmd::{
    ParamKind, ParamSetRequest, ParamSetRequestArgs, ParamValue, ParamValueArgs,
};

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);
const TEAM_A: &str = "team-alpha";
const TEAM_B: &str = "team-beta";

struct PolicyFixture {
    policy: CommandPolicy,
    config: PolicyConfig,
    directory: PathBuf,
    team: String,
}

impl Deref for PolicyFixture {
    type Target = CommandPolicy;

    fn deref(&self) -> &Self::Target {
        &self.policy
    }
}

impl Drop for PolicyFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn policy() -> PolicyFixture {
    fixture(TEAM_A)
}

fn fixture(team: &str) -> PolicyFixture {
    let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "electrode-command-authority-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).unwrap();
    let mut config = PolicyConfig::default();
    config.velocity_budget_json = directory.join("budget.json");
    config.velocity_budget_csv = directory.join("budget.csv");
    PolicyFixture {
        policy: CommandPolicy::new(config.clone()),
        config,
        directory,
        team: team.to_string(),
    }
}

/// The public 16-hex credential id the authority derives from a team name.
fn credential_id(team: &str) -> String {
    let full: String = Sha256::digest(team.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    full[..16].to_string()
}

#[test]
fn default_runtime_uses_distinct_browser_and_vehicle_transports() {
    let config = CommandAuthorityConfig::default();
    assert!(config.browser_listen.starts_with("ws/"));
    assert!(config.vehicle_listen.starts_with("udp/"));
    assert_ne!(config.browser_listen, config.vehicle_listen);
}

fn velocity(x: f32, y: f32, z: f32) -> Vec<u8> {
    let mut payload = vec![0_u8; 56];
    payload[20..24].copy_from_slice(&x.to_le_bytes());
    payload[24..28].copy_from_slice(&y.to_le_bytes());
    payload[28..32].copy_from_slice(&z.to_le_bytes());
    payload[52..54].copy_from_slice(&3527_u16.to_le_bytes());
    payload
}

fn velocity_intent(team: &str, x: f32, y: f32, z: f32) -> Vec<u8> {
    envelope(b"EVC1", team, &velocity(x, y, z))
}

fn velocity_budget_request(team: &str) -> Vec<u8> {
    envelope(b"EVB1", team, &[])
}

fn raw_velocity_intent(team: &str, payload: &[u8]) -> Vec<u8> {
    envelope(b"EVR1", team, payload)
}

/// Team-name credential envelope: `magic(4) | name_len(1) | name | payload`.
fn envelope(magic: &[u8; 4], team: &str, payload: &[u8]) -> Vec<u8> {
    let name = team.as_bytes();
    let mut envelope = Vec::with_capacity(5 + name.len() + payload.len());
    envelope.extend_from_slice(magic);
    envelope.push(name.len() as u8);
    envelope.extend_from_slice(name);
    envelope.extend_from_slice(payload);
    envelope
}

fn manual(flags: u8) -> Vec<u8> {
    let mut payload = vec![0_u8; 40];
    payload[12..14].copy_from_slice(&15_u16.to_le_bytes());
    payload[18..20].copy_from_slice(&700_i16.to_le_bytes());
    payload[35] = flags;
    payload
}

fn radio(channel: u16) -> Vec<u8> {
    let mut payload = vec![0_u8; 48];
    payload[8] = 5;
    payload[9] = 100;
    for index in 0..5 {
        let offset = 10 + index * 2;
        payload[offset..offset + 2].copy_from_slice(&channel.to_le_bytes());
    }
    payload
}

fn parameter(name: &str, value: f64) -> Vec<u8> {
    let mut builder = FlatBufferBuilder::new();
    let name = builder.create_string(name);
    let parameter = ParamValue::create(
        &mut builder,
        &ParamValueArgs {
            name: Some(name),
            kind: ParamKind::Float,
            float_value: value,
            ..Default::default()
        },
    );
    let request = ParamSetRequest::create(
        &mut builder,
        &ParamSetRequestArgs {
            value: Some(parameter),
        },
    );
    builder.finish(request, None);
    builder.finished_data().to_vec()
}

#[test]
fn maps_only_valid_x_velocity_and_enforces_budget() {
    let policy = policy();
    let bare = velocity(2.5, 0.0, 0.0);
    let command = policy
        .authorize(
            "gcs/v1/cmd/velocity",
            &velocity_intent(&policy.team, 2.5, 0.0, 0.0),
        )
        .unwrap();
    assert_eq!(command.delivery, Delivery::Publish);
    assert_eq!(command.target, "synapse/v1/topic/local_position_command");
    assert_eq!(command.payload, bare);
    assert_eq!(command.velocity_used, Some(1));
    assert_eq!(command.velocity_remaining, Some(4));
    let first_version = command
        .velocity_budget_version
        .as_deref()
        .unwrap()
        .parse::<u128>()
        .unwrap();
    let expected_credential = credential_id(&policy.team);
    assert_eq!(
        command.velocity_credential_id.as_deref(),
        Some(expected_credential.as_str())
    );
    assert!(policy
        .authorize(
            "gcs/v1/cmd/velocity",
            &velocity_intent(&policy.team, 2.5, 0.1, 0.0),
        )
        .is_err());
    for _ in 0..4 {
        policy
            .authorize(
                "gcs/v1/cmd/velocity",
                &velocity_intent(&policy.team, 1.0, 0.0, 0.0),
            )
            .unwrap();
    }
    assert!(policy
        .authorize(
            "gcs/v1/cmd/velocity",
            &velocity_intent(&policy.team, 1.0, 0.0, 0.0),
        )
        .is_err());
    let state = policy
        .authorize(
            "gcs/v1/cmd/velocity_budget",
            &velocity_budget_request(&policy.team),
        )
        .unwrap();
    assert_eq!(state.delivery, Delivery::Budget);
    assert_eq!(state.velocity_used, Some(5));
    assert_eq!(state.velocity_remaining, Some(0));
    assert!(
        state
            .velocity_budget_version
            .as_deref()
            .unwrap()
            .parse::<u128>()
            .unwrap()
            > first_version
    );
}

#[test]
fn typed_manual_and_radio_have_exact_mappings_and_ranges() {
    let policy = policy();
    assert_eq!(
        policy
            .authorize("gcs/v1/cmd/manual", &manual(12))
            .unwrap()
            .target,
        "synapse/v1/topic/manual_control_command"
    );
    assert!(policy.authorize("gcs/v1/cmd/manual", &manual(0)).is_err());
    assert_eq!(
        policy
            .authorize("gcs/v1/cmd/radio", &radio(1500))
            .unwrap()
            .target,
        "synapse/v1/topic/radio_control"
    );
    assert!(policy.authorize("gcs/v1/cmd/radio", &radio(899)).is_err());
    assert!(policy.authorize("gcs/v1/cmd/radio", &radio(2101)).is_err());
}

#[test]
fn gain_is_schema_verified_and_allowlisted() {
    let policy = policy();
    let command = policy
        .authorize("gcs/v1/cmd/gain", &parameter("attitude.headingPid.kp", 1.2))
        .unwrap();
    assert_eq!(command.delivery, Delivery::Query);
    assert_eq!(command.target, "synapse/v1/cmd/param_set");
    assert!(policy
        .authorize(
            "gcs/v1/cmd/gain",
            &parameter("attitude.headingPid.trim", 1.0),
        )
        .is_err());
    assert!(policy
        .authorize(
            "gcs/v1/cmd/config",
            &parameter("attitude.headingPid.kp", 1.2),
        )
        .is_err());
}

#[test]
fn raw_path_is_one_bounded_leaf_and_preserves_selected_topics() {
    let policy = policy();
    assert_eq!(
        policy
            .authorize("gcs/v1/cmd/raw/text_status", b"operator bytes")
            .unwrap()
            .target,
        "synapse/v1/topic/text_status"
    );
    let payload = (0_u8..40).collect::<Vec<_>>();
    let command = policy
        .authorize("gcs/v1/cmd/raw/manual_control_command", &payload)
        .unwrap();
    assert_eq!(command.target, "synapse/v1/topic/manual_control_command");
    assert_eq!(command.payload, payload);
    assert!(policy
        .authorize(
            "gcs/v1/cmd/raw/local_position_command",
            &velocity(2.0, 0.0, 0.0),
        )
        .is_err());
    let arbitrary = (0_u8..37).collect::<Vec<_>>();
    let command = policy
        .authorize(
            "gcs/v1/cmd/raw/local_position_command",
            &raw_velocity_intent(&policy.team, &arbitrary),
        )
        .unwrap();
    assert_eq!(command.payload, arbitrary);
    assert_eq!(command.status_leaf, "velocity");
    assert_eq!(command.velocity_remaining, Some(4));
    assert!(policy
        .authorize("gcs/v1/cmd/raw/nested/channel", &[0; 16])
        .is_err());
    assert!(policy
        .authorize("gcs/v1/cmd/raw/text_status", &vec![0; 4097])
        .is_err());
}

#[test]
fn bare_velocity_and_invalid_team_names_fail_while_new_teams_auto_enroll() {
    let policy = policy();
    // No credential envelope at all.
    assert!(policy
        .authorize("gcs/v1/cmd/velocity", &velocity(2.0, 0.0, 0.0))
        .is_err());
    // A syntactically invalid team name (contains a space) is rejected.
    assert!(policy
        .authorize(
            "gcs/v1/cmd/velocity",
            &velocity_intent("bad team", 2.0, 0.0, 0.0),
        )
        .is_err());
    // A brand-new valid team auto-enrolls, creating its budget row on first use.
    let command = policy
        .authorize(
            "gcs/v1/cmd/velocity",
            &velocity_intent("team-newcomer", 2.0, 0.0, 0.0),
        )
        .unwrap();
    assert_eq!(command.velocity_used, Some(1));
    assert_eq!(command.velocity_remaining, Some(4));
    assert!(policy.config.velocity_budget_csv.exists());
}

#[test]
fn budget_survives_policy_restart() {
    let policy = policy();
    for _ in 0..2 {
        policy
            .authorize(
                "gcs/v1/cmd/velocity",
                &velocity_intent(&policy.team, 2.0, 0.0, 0.0),
            )
            .unwrap();
    }
    let restarted = CommandPolicy::new(policy.config.clone());
    let state = restarted
        .authorize(
            "gcs/v1/cmd/velocity_budget",
            &velocity_budget_request(&policy.team),
        )
        .unwrap();
    assert_eq!(state.velocity_used, Some(2));
    assert_eq!(state.velocity_remaining, Some(3));
}

#[test]
fn json_without_csv_and_empty_csv_fail_closed() {
    let policy = policy();
    fs::write(
        &policy.config.velocity_budget_json,
        b"{\"version\":1,\"devices\":{}}",
    )
    .unwrap();
    let missing_csv = policy
        .authorize(
            "gcs/v1/cmd/velocity_budget",
            &velocity_budget_request(&policy.team),
        )
        .unwrap_err()
        .to_string();
    assert!(missing_csv.contains("authoritative velocity budget CSV"));
    assert!(!policy.config.velocity_budget_csv.exists());

    fs::write(&policy.config.velocity_budget_csv, []).unwrap();
    let empty_csv = policy
        .authorize(
            "gcs/v1/cmd/velocity_budget",
            &velocity_budget_request(&policy.team),
        )
        .unwrap_err()
        .to_string();
    assert!(empty_csv.contains("empty or has an invalid header"));
}

#[test]
fn programmatic_budget_above_five_is_normalized_in_authorized_state() {
    let fixture = policy();
    let mut config = fixture.config.clone();
    config.velocity_budget = 99;
    let policy = CommandPolicy::new(config);
    let state = policy
        .authorize(
            "gcs/v1/cmd/velocity_budget",
            &velocity_budget_request(&fixture.team),
        )
        .unwrap();
    assert_eq!(state.velocity_limit, Some(5));
    assert_eq!(state.velocity_remaining, Some(5));
}

#[test]
fn a_budget_check_alone_does_not_register_a_team() {
    let policy = policy();
    // Checking the budget for a never-used team returns a full 5/5 without
    // writing any CSV row: registration happens only on the first command.
    let state = policy
        .authorize(
            "gcs/v1/cmd/velocity_budget",
            &velocity_budget_request("team-checking"),
        )
        .unwrap();
    assert_eq!(state.velocity_used, Some(0));
    assert_eq!(state.velocity_remaining, Some(5));
    assert!(!policy.config.velocity_budget_csv.exists());

    // The first velocity command registers the team by creating its row.
    policy
        .authorize(
            "gcs/v1/cmd/velocity",
            &velocity_intent("team-checking", 2.0, 0.0, 0.0),
        )
        .unwrap();
    assert!(policy.config.velocity_budget_csv.exists());
    let csv = fs::read_to_string(&policy.config.velocity_budget_csv).unwrap();
    assert!(csv.contains("team-checking,1,5"));
}

#[test]
fn csv_is_authoritative_and_only_deleted_team_row_resets() {
    let policy = policy();
    for _ in 0..2 {
        policy
            .authorize("gcs/v1/cmd/velocity", &velocity_intent(TEAM_A, 2.0, 0.0, 0.0))
            .unwrap();
    }
    policy
        .authorize("gcs/v1/cmd/velocity", &velocity_intent(TEAM_B, 2.0, 0.0, 0.0))
        .unwrap();

    fs::write(
        &policy.config.velocity_budget_json,
        b"{\"version\":1,\"devices\":{}}",
    )
    .unwrap();
    let csv_preserved = policy
        .authorize("gcs/v1/cmd/velocity_budget", &velocity_budget_request(TEAM_A))
        .unwrap();
    assert_eq!(csv_preserved.velocity_used, Some(2));

    let csv = fs::read_to_string(&policy.config.velocity_budget_csv).unwrap();
    let without_team_a = csv
        .lines()
        .filter(|line| !line.starts_with("team-alpha,"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(&policy.config.velocity_budget_csv, without_team_a).unwrap();

    let reset_a = policy
        .authorize("gcs/v1/cmd/velocity_budget", &velocity_budget_request(TEAM_A))
        .unwrap();
    let unchanged_b = policy
        .authorize("gcs/v1/cmd/velocity_budget", &velocity_budget_request(TEAM_B))
        .unwrap();
    assert_eq!(reset_a.velocity_used, Some(0));
    assert_eq!(reset_a.velocity_remaining, Some(5));
    assert_eq!(unchanged_b.velocity_used, Some(1));
    assert_eq!(unchanged_b.velocity_remaining, Some(4));
}

#[test]
fn duplicate_csv_team_rows_fail_closed() {
    let policy = policy();
    // Consume one command so the team's CSV row exists (a budget read alone no
    // longer creates a row).
    policy
        .authorize(
            "gcs/v1/cmd/velocity",
            &velocity_intent(&policy.team, 2.0, 0.0, 0.0),
        )
        .unwrap();
    let csv = fs::read_to_string(&policy.config.velocity_budget_csv).unwrap();
    let team_row = csv.lines().nth(1).unwrap();
    fs::write(
        &policy.config.velocity_budget_csv,
        format!("{csv}{team_row}\n"),
    )
    .unwrap();

    let error = policy
        .authorize(
            "gcs/v1/cmd/velocity_budget",
            &velocity_budget_request(&policy.team),
        )
        .unwrap_err()
        .to_string();
    assert!(error.contains("duplicate device id"));
}

#[test]
fn concurrent_velocity_intents_cannot_exceed_five() {
    let fixture = policy();
    let policy = Arc::new(CommandPolicy::new(fixture.config.clone()));
    let mut workers = Vec::new();
    for _ in 0..12 {
        let policy = Arc::clone(&policy);
        workers.push(std::thread::spawn(move || {
            policy
                .authorize("gcs/v1/cmd/velocity", &velocity_intent(TEAM_A, 2.0, 0.0, 0.0))
                .is_ok()
        }));
    }
    let accepted = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .filter(|accepted| *accepted)
        .count();
    assert_eq!(accepted, 5);
    let state = policy
        .authorize("gcs/v1/cmd/velocity_budget", &velocity_budget_request(TEAM_A))
        .unwrap();
    assert_eq!(state.velocity_used, Some(5));
    assert_eq!(state.velocity_remaining, Some(0));
}

#[test]
fn firmware_upload_uses_staged_authority_delivery() {
    let policy = policy();
    assert_eq!(
        PolicyConfig::default().firmware_key_prefix,
        "synapse/v1/cmd/firmware"
    );
    assert!(CANONICAL_FIRMWARE_QUERY_KEYS.contains(&"synapse/v1/cmd/firmware_abort"));
    let command = policy
        .authorize("gcs/v1/cmd/firmware/update-1/start", &[0; 32])
        .unwrap();
    assert_eq!(command.delivery, Delivery::Firmware);
    assert_eq!(command.target, "update-1/start");
    assert_eq!(command.status_leaf, "firmware/update-1");
    assert_eq!(command.payload, vec![0; 32]);
    assert!(policy
        .authorize("gcs/v1/cmd/firmware/update-1/chunk/2", &[1; 64])
        .is_ok());
    assert!(policy
        .authorize(
            "gcs/v1/cmd/firmware/update-1/chunk/2",
            &vec![1; 68 * 1024 + 1]
        )
        .is_err());
    assert!(policy
        .authorize("gcs/v1/cmd/firmware/../commit", &[0; 32])
        .is_err());
    assert!(policy
        .authorize("gcs/v1/cmd/firmware_info", &[0; 32])
        .is_err());
}
