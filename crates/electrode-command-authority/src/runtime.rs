//! Zenoh runtime with a hard browser/vehicle session boundary.

use std::env;
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{anyhow, Result};
use synapse_fbs::cmd::ParamSetReply;
use synapse_fbs::topic::MocapFrame;
use synapse_fbs::types::CommandResultCode;
use zenoh::{Session, Wait};

use crate::firmware_gate::{publish_policy_rejection, FirmwareGate};
use crate::policy::{AuthorizedCommand, CommandPolicy, Delivery, PolicyConfig};
use crate::velocity_budget::BudgetState;

const PARAMETER_QUEUE_CAPACITY: usize = 8;
const PRIVATE_MOCAP_TOPIC: &str = "electrode/sim/rumoca/mocap_frame";
const PRIVATE_PWM_TOPIC: &str = "electrode/sim/rumoca/radio_pwm_signal_outputs";

/// Runtime endpoints. The two sessions never discover one another directly.
#[derive(Clone, Debug)]
pub struct CommandAuthorityConfig {
    pub browser_listen: String,
    pub browser_connect: Option<String>,
    pub vehicle_listen: String,
    pub vehicle_connect: Option<String>,
    pub query_timeout: Duration,
    pub policy: PolicyConfig,
}

impl Default for CommandAuthorityConfig {
    fn default() -> Self {
        Self {
            browser_listen: "ws/0.0.0.0:7447".to_string(),
            browser_connect: None,
            vehicle_listen: "udp/0.0.0.0:7447".to_string(),
            vehicle_connect: None,
            query_timeout: Duration::from_secs(2),
            policy: PolicyConfig::default(),
        }
    }
}

impl CommandAuthorityConfig {
    #[must_use]
    pub fn from_env() -> Self {
        let defaults = Self::default();
        Self {
            browser_listen: value_or("ELECTRODE_GCS_ZENOH_WS_LISTEN", defaults.browser_listen),
            browser_connect: optional("ELECTRODE_GCS_BROWSER_ZENOH_CONNECT"),
            vehicle_listen: value_or("ELECTRODE_GCS_ZENOH_LISTEN", defaults.vehicle_listen),
            vehicle_connect: optional("ELECTRODE_GCS_ZENOH_CONNECT"),
            query_timeout: Duration::from_millis(
                env::var("ELECTRODE_GCS_QUERY_TIMEOUT_MS")
                    .ok()
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(2_000)
                    .clamp(100, 60_000),
            ),
            policy: PolicyConfig {
                intent_prefix: value_or(
                    "ELECTRODE_GCS_INTENT_PREFIX",
                    defaults.policy.intent_prefix,
                ),
                vehicle_topic_prefix: value_or(
                    "ELECTRODE_GCS_VEHICLE_TOPIC_PREFIX",
                    defaults.policy.vehicle_topic_prefix,
                ),
                parameter_key: value_or(
                    "ELECTRODE_GCS_PARAMETER_KEY",
                    defaults.policy.parameter_key,
                ),
                firmware_key_prefix: value_or(
                    "ELECTRODE_GCS_FIRMWARE_KEY_PREFIX",
                    defaults.policy.firmware_key_prefix,
                ),
                velocity_min_mps: 1.0,
                velocity_max_mps: 4.0,
                velocity_budget: env::var("ELECTRODE_GCS_VELOCITY_BUDGET")
                    .ok()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(defaults.policy.velocity_budget)
                    .clamp(1, 5),
                velocity_budget_json: path_or(
                    "ELECTRODE_GCS_VELOCITY_BUDGET_DB",
                    defaults.policy.velocity_budget_json,
                ),
                velocity_budget_csv: path_or(
                    "ELECTRODE_GCS_VELOCITY_BUDGET_CSV",
                    defaults.policy.velocity_budget_csv,
                ),
                raw_max_bytes: defaults.policy.raw_max_bytes,
            },
        }
    }
}

/// Owns both isolated sessions and all allowlisted relays.
pub struct CommandAuthority {
    browser_session: Session,
    vehicle_session: Session,
    subscribers: Vec<zenoh::pubsub::Subscriber<()>>,
    query_sender: Option<SyncSender<AuthorizedCommand>>,
    query_worker: Option<JoinHandle<()>>,
    listeners: Vec<String>,
}

impl CommandAuthority {
    pub fn start(config: CommandAuthorityConfig) -> Result<Self> {
        let browser_session =
            open_session(&config.browser_listen, config.browser_connect.as_deref())?;
        let vehicle_session =
            open_session(&config.vehicle_listen, config.vehicle_connect.as_deref())?;
        let policy = Arc::new(CommandPolicy::new(config.policy.clone()));
        let firmware_gate = Arc::new(FirmwareGate::from_env(
            config.policy.firmware_key_prefix.clone(),
            config.query_timeout,
        ));
        let (query_sender, query_receiver) =
            sync_channel::<AuthorizedCommand>(PARAMETER_QUEUE_CAPACITY);
        let worker_vehicle = vehicle_session.clone();
        let worker_browser = browser_session.clone();
        let worker_config = config.clone();
        let worker_firmware_gate = firmware_gate;
        let query_worker = std::thread::Builder::new()
            .name("electrode-command-query".to_string())
            .spawn(move || {
                while let Ok(command) = query_receiver.recv() {
                    match command.delivery {
                        Delivery::Query => {
                            execute_query(&worker_vehicle, &worker_browser, &worker_config, command)
                        }
                        Delivery::Firmware => worker_firmware_gate.handle_intent(
                            &worker_vehicle,
                            &worker_browser,
                            &worker_config.policy.intent_prefix,
                            &command.target,
                            &command.payload,
                        ),
                        Delivery::Publish => {
                            tracing::error!("publish command reached query worker")
                        }
                        Delivery::Budget => {
                            tracing::error!("budget command reached query worker")
                        }
                    }
                }
            })
            .map_err(|error| anyhow!("start command query worker: {error}"))?;

        let subscribers = vec![
            subscribe_intents(
                &browser_session,
                &vehicle_session,
                policy,
                query_sender.clone(),
                &config,
            )?,
            relay_to_browser(&vehicle_session, &browser_session, "synapse/v1/topic/**")?,
            relay_to_browser(&vehicle_session, &browser_session, "synapse/mocap/**")?,
            relay_to_browser(&vehicle_session, &browser_session, PRIVATE_PWM_TOPIC)?,
            relay_verified_mocap(&browser_session, &vehicle_session)?,
        ];
        let listeners = [config.vehicle_listen.clone(), config.browser_listen.clone()]
            .into_iter()
            .filter(|endpoint| !endpoint.trim().is_empty())
            .collect::<Vec<_>>();

        tracing::info!(
            browser = %config.browser_listen,
            vehicle = %config.vehicle_listen,
            intents = %config.policy.intent_prefix,
            "isolated command authority listening"
        );
        Ok(Self {
            browser_session,
            vehicle_session,
            subscribers,
            query_sender: Some(query_sender),
            query_worker: Some(query_worker),
            listeners,
        })
    }

    #[must_use]
    pub fn listeners(&self) -> &[String] {
        &self.listeners
    }
}

impl Drop for CommandAuthority {
    fn drop(&mut self) {
        self.subscribers.clear();
        self.query_sender.take();
        if let Some(worker) = self.query_worker.take() {
            if worker.join().is_err() {
                tracing::warn!("command query worker panicked during shutdown");
            }
        }
        let _ = self.browser_session.close().wait();
        let _ = self.vehicle_session.close().wait();
    }
}

fn subscribe_intents(
    browser: &Session,
    vehicle: &Session,
    policy: Arc<CommandPolicy>,
    query_sender: SyncSender<AuthorizedCommand>,
    config: &CommandAuthorityConfig,
) -> Result<zenoh::pubsub::Subscriber<()>> {
    let key = format!("{}/**", config.policy.intent_prefix.trim_end_matches('/'));
    let callback_vehicle = vehicle.clone();
    let callback_browser = browser.clone();
    let callback_config = config.clone();
    browser
        .declare_subscriber(key.clone())
        .callback(move |sample| {
            let intent_key = sample.key_expr().as_str();
            let payload = sample.payload().to_bytes();
            match policy.authorize(intent_key, &payload) {
                Ok(command) if command.delivery == Delivery::Publish => {
                    execute_publish(
                        &callback_vehicle,
                        &callback_browser,
                        &callback_config,
                        policy.as_ref(),
                        command,
                    );
                }
                Ok(command) if command.delivery == Delivery::Budget => {
                    publish_velocity_command_status(
                        &callback_browser,
                        &callback_config,
                        "state",
                        &command,
                        "authoritative velocity budget",
                    );
                }
                Ok(command) => {
                    enqueue_query(&query_sender, &callback_browser, &callback_config, command)
                }
                Err(error) => {
                    tracing::warn!(key = intent_key, %error, "browser command rejected");
                    publish_policy_error(
                        &callback_browser,
                        &callback_config,
                        policy.as_ref(),
                        intent_key,
                        &payload,
                        &error.to_string(),
                    );
                }
            }
        })
        .wait()
        .map_err(|error| anyhow!("subscribe browser intents {key}: {error}"))
}

fn publish_policy_error(
    browser: &Session,
    config: &CommandAuthorityConfig,
    policy: &CommandPolicy,
    intent_key: &str,
    payload: &[u8],
    message: &str,
) {
    let prefix = format!("{}/", config.policy.intent_prefix.trim_end_matches('/'));
    let suffix = intent_key.strip_prefix(&prefix).unwrap_or("");
    match suffix {
        "velocity" | "velocity_budget" | "raw/local_position_command" => {
            match policy.velocity_state_for_payload(payload) {
                Ok(state) => publish_velocity_status(browser, config, "rejected", &state, message),
                Err(_) => publish_unknown_velocity_status(
                    browser,
                    config,
                    CommandPolicy::credential_id_for_payload(payload).as_deref(),
                    message,
                ),
            }
        }
        "gain" => publish_status(browser, config, "gain", "rejected", message),
        firmware if firmware.starts_with("firmware/") => {
            let update_id = firmware[9..].split('/').next().unwrap_or("");
            if !publish_policy_rejection(browser, &config.policy.intent_prefix, update_id, message)
            {
                publish_status(browser, config, "command", "rejected", message);
            }
        }
        _ => publish_status(browser, config, "command", "rejected", message),
    }
}

fn execute_publish(
    vehicle: &Session,
    browser: &Session,
    config: &CommandAuthorityConfig,
    policy: &CommandPolicy,
    command: AuthorizedCommand,
) {
    let result = vehicle.put(&command.target, command.payload.clone()).wait();
    if let Err(error) = result {
        if let (Some(device), Some(credential_id)) = (
            command.velocity_device.as_deref(),
            command.velocity_credential_id.as_deref(),
        ) {
            match policy.refund_velocity(device, credential_id) {
                Ok(state) => {
                    publish_velocity_status(browser, config, "failed", &state, &error.to_string())
                }
                Err(refund_error) => publish_velocity_command_status(
                    browser,
                    config,
                    "failed",
                    &command,
                    &format!("{error}; velocity budget refund failed: {refund_error}"),
                ),
            }
        } else {
            publish_status(
                browser,
                config,
                &command.status_leaf,
                "failed",
                &error.to_string(),
            );
        }
        return;
    }
    if command.velocity_remaining.is_some() {
        publish_velocity_command_status(
            browser,
            config,
            "accepted",
            &command,
            "command forwarded to the vehicle session",
        );
    } else {
        publish_status(
            browser,
            config,
            &command.status_leaf,
            "accepted",
            "command forwarded to the vehicle session",
        );
    }
}

fn enqueue_query(
    sender: &SyncSender<AuthorizedCommand>,
    browser: &Session,
    config: &CommandAuthorityConfig,
    command: AuthorizedCommand,
) {
    let status_leaf = command.status_leaf.clone();
    let message = match sender.try_send(command) {
        Ok(()) => return,
        Err(TrySendError::Full(_)) => "command query queue is full",
        Err(TrySendError::Disconnected(_)) => "command query worker is unavailable",
    };
    publish_status(browser, config, &status_leaf, "rejected", message);
}

fn execute_query(
    vehicle: &Session,
    browser: &Session,
    config: &CommandAuthorityConfig,
    command: AuthorizedCommand,
) {
    let replies = match vehicle
        .get(&command.target)
        .payload(command.payload)
        .timeout(config.query_timeout)
        .wait()
    {
        Ok(replies) => replies,
        Err(error) => {
            publish_status(
                browser,
                config,
                &command.status_leaf,
                "rejected",
                &error.to_string(),
            );
            return;
        }
    };
    match replies.recv_timeout(config.query_timeout) {
        Ok(Some(reply)) => match reply.into_result() {
            Ok(sample) => {
                let payload = sample.payload().to_bytes().to_vec();
                let reply_key = format!(
                    "{}/reply/{}",
                    status_prefix(&config.policy.intent_prefix),
                    command.status_leaf
                );
                let _ = browser.put(reply_key, payload.clone()).wait();
                match parameter_reply_status(&payload) {
                    Ok((status, message)) => {
                        publish_status(browser, config, &command.status_leaf, status, &message)
                    }
                    Err(error) => publish_status(
                        browser,
                        config,
                        &command.status_leaf,
                        "rejected",
                        &error.to_string(),
                    ),
                }
            }
            Err(error) => publish_status(
                browser,
                config,
                &command.status_leaf,
                "rejected",
                &error.to_string(),
            ),
        },
        Ok(None) => publish_status(
            browser,
            config,
            &command.status_leaf,
            "rejected",
            "target service returned no reply",
        ),
        Err(error) => publish_status(
            browser,
            config,
            &command.status_leaf,
            "rejected",
            &error.to_string(),
        ),
    }
}

fn parameter_reply_status(payload: &[u8]) -> Result<(&'static str, String)> {
    let reply = flatbuffers::root::<ParamSetReply<'_>>(payload)
        .map_err(|error| anyhow!("invalid ParamSetReply: {error}"))?;
    let result = reply.result();
    let detail = reply.result_detail();
    match result {
        CommandResultCode::Accepted => Ok(("accepted", "target service accepted the gain".into())),
        CommandResultCode::InProgress => {
            Ok(("in_progress", "target service is applying the gain".into()))
        }
        _ => Err(anyhow!(
            "target service returned {} (detail {detail})",
            result.variant_name().unwrap_or("unknown result")
        )),
    }
}

fn relay_to_browser(
    vehicle: &Session,
    browser: &Session,
    key: &str,
) -> Result<zenoh::pubsub::Subscriber<()>> {
    let destination = browser.clone();
    vehicle
        .declare_subscriber(key)
        .callback(move |sample| {
            let key = sample.key_expr().as_str().to_string();
            let payload = sample.payload().to_bytes().to_vec();
            if let Err(error) = destination.put(key.clone(), payload).wait() {
                tracing::warn!(%key, %error, "vehicle telemetry relay failed");
            }
        })
        .wait()
        .map_err(|error| anyhow!("subscribe vehicle relay {key}: {error}"))
}

fn relay_verified_mocap(
    browser: &Session,
    vehicle: &Session,
) -> Result<zenoh::pubsub::Subscriber<()>> {
    let destination = vehicle.clone();
    browser
        .declare_subscriber(PRIVATE_MOCAP_TOPIC)
        .callback(move |sample| {
            let payload = sample.payload().to_bytes();
            if flatbuffers::root::<MocapFrame<'_>>(&payload).is_err() {
                tracing::warn!("invalid private MocapFrame dropped at browser boundary");
                return;
            }
            if let Err(error) = destination.put(PRIVATE_MOCAP_TOPIC, payload).wait() {
                tracing::warn!(%error, "private MocapFrame relay failed");
            }
        })
        .wait()
        .map_err(|error| anyhow!("subscribe private MocapFrame: {error}"))
}

fn publish_status(
    browser: &Session,
    config: &CommandAuthorityConfig,
    leaf: &str,
    status: &str,
    message: &str,
) {
    let key = format!(
        "{}/status/{leaf}",
        status_prefix(&config.policy.intent_prefix)
    );
    let payload = serde_json::json!({ "status": status, "message": message }).to_string();
    if let Err(error) = browser.put(key.clone(), payload).wait() {
        tracing::warn!(%key, %error, "browser status publish failed");
    }
}

fn publish_velocity_status(
    browser: &Session,
    config: &CommandAuthorityConfig,
    status: &str,
    state: &BudgetState,
    message: &str,
) {
    publish_velocity_status_fields(
        browser,
        config,
        status,
        Some(&state.device_id),
        Some(&state.credential_id),
        state.limit,
        state.used,
        state.remaining,
        Some(&state.budget_version),
        message,
    );
}

fn publish_velocity_command_status(
    browser: &Session,
    config: &CommandAuthorityConfig,
    status: &str,
    command: &AuthorizedCommand,
    message: &str,
) {
    publish_velocity_status_fields(
        browser,
        config,
        status,
        command.velocity_device.as_deref(),
        command.velocity_credential_id.as_deref(),
        command
            .velocity_limit
            .unwrap_or(config.policy.velocity_budget.clamp(1, 5)),
        command
            .velocity_used
            .unwrap_or(config.policy.velocity_budget),
        command.velocity_remaining.unwrap_or(0),
        command.velocity_budget_version.as_deref(),
        message,
    );
}

fn publish_unknown_velocity_status(
    browser: &Session,
    config: &CommandAuthorityConfig,
    credential_id: Option<&str>,
    message: &str,
) {
    publish_velocity_status_fields(
        browser,
        config,
        "rejected",
        None,
        credential_id,
        config.policy.velocity_budget.clamp(1, 5),
        config.policy.velocity_budget.clamp(1, 5),
        0,
        None,
        message,
    );
}

#[allow(clippy::too_many_arguments)]
fn publish_velocity_status_fields(
    browser: &Session,
    config: &CommandAuthorityConfig,
    status: &str,
    device_id: Option<&str>,
    credential_id: Option<&str>,
    limit: u32,
    used: u32,
    remaining: u32,
    budget_version: Option<&str>,
    message: &str,
) {
    let credential_suffix = credential_id
        .map(|value| format!("/{value}"))
        .unwrap_or_default();
    let key = format!(
        "{}/status/velocity{credential_suffix}",
        status_prefix(&config.policy.intent_prefix),
    );
    let payload = serde_json::json!({
        "status": status,
        "message": message,
        "deviceId": device_id,
        "credentialId": credential_id,
        "limit": limit,
        "used": used,
        "remaining": remaining,
        "budgetVersion": budget_version,
    })
    .to_string();
    if let Err(error) = browser.put(key.clone(), payload).wait() {
        tracing::warn!(%key, %error, "browser velocity status publish failed");
    }
}

fn status_prefix(intent_prefix: &str) -> &str {
    intent_prefix.strip_suffix("/cmd").unwrap_or(intent_prefix)
}

fn open_session(listen: &str, connect: Option<&str>) -> Result<Session> {
    let mut config = zenoh::Config::default();
    config
        .insert_json5("mode", "\"peer\"")
        .map_err(|error| anyhow!(error.to_string()))?;
    if !listen.trim().is_empty() {
        config
            .insert_json5("listen/endpoints", &format!("[\"{}\"]", listen.trim()))
            .map_err(|error| anyhow!(error.to_string()))?;
    }
    if let Some(connect) = connect.filter(|endpoint| !endpoint.trim().is_empty()) {
        config
            .insert_json5("connect/endpoints", &format!("[\"{}\"]", connect.trim()))
            .map_err(|error| anyhow!(error.to_string()))?;
    }
    config
        .insert_json5("scouting/multicast/enabled", "false")
        .map_err(|error| anyhow!(error.to_string()))?;
    zenoh::open(config)
        .wait()
        .map_err(|error| anyhow!("open isolated Zenoh session: {error}"))
}

fn optional(key: &str) -> Option<String> {
    env::var(key).ok().filter(|value| !value.trim().is_empty())
}

fn value_or(key: &str, default: String) -> String {
    optional(key).unwrap_or(default)
}

fn path_or(key: &str, default: std::path::PathBuf) -> std::path::PathBuf {
    optional(key).map_or(default, std::path::PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::parameter_reply_status;
    use flatbuffers::FlatBufferBuilder;
    use synapse_fbs::cmd::{ParamSetReply, ParamSetReplyArgs};
    use synapse_fbs::types::CommandResultCode;

    fn reply(result: CommandResultCode, result_detail: i32) -> Vec<u8> {
        let mut builder = FlatBufferBuilder::new();
        let reply = ParamSetReply::create(
            &mut builder,
            &ParamSetReplyArgs {
                result,
                result_detail,
                ..Default::default()
            },
        );
        builder.finish(reply, None);
        builder.finished_data().to_vec()
    }

    #[test]
    fn parameter_reply_result_controls_browser_status() {
        assert_eq!(
            parameter_reply_status(&reply(CommandResultCode::Accepted, 0))
                .unwrap()
                .0,
            "accepted"
        );
        assert_eq!(
            parameter_reply_status(&reply(CommandResultCode::InProgress, 0))
                .unwrap()
                .0,
            "in_progress"
        );
        let denied = parameter_reply_status(&reply(CommandResultCode::Denied, 7))
            .unwrap_err()
            .to_string();
        assert!(denied.contains("Denied"));
        assert!(denied.contains("detail 7"));
    }
}
