//! Persistent, team-scoped velocity command accounting.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const CSV_HEADER: &str =
    "device_id,used,limit,created_at,updated_at,last_velocity_mps,last_applied_at\n";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Credential {
    pub(crate) device_id: String,
    pub(crate) credential_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BudgetState {
    pub(crate) device_id: String,
    pub(crate) credential_id: String,
    pub(crate) limit: u32,
    pub(crate) used: u32,
    pub(crate) remaining: u32,
    pub(crate) budget_version: String,
}

#[derive(Clone, Debug)]
pub(crate) struct VelocityBudgetStore {
    json_path: PathBuf,
    csv_path: PathBuf,
    limit: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct DeviceRecord {
    device_id: String,
    used: u32,
    limit: u32,
    created_at: String,
    updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_velocity_mps: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_applied_at: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct BudgetDatabase {
    #[serde(default = "version_one")]
    version: u32,
    #[serde(default)]
    devices: HashMap<String, DeviceRecord>,
}

impl Default for BudgetDatabase {
    fn default() -> Self {
        Self {
            version: 1,
            devices: HashMap::new(),
        }
    }
}

impl VelocityBudgetStore {
    pub(crate) fn new(json_path: PathBuf, csv_path: PathBuf, limit: u32) -> Self {
        Self {
            json_path,
            csv_path,
            limit: limit.clamp(1, 5),
        }
    }

    /// A team name is a self-asserted identity. Any syntactically valid name
    /// resolves to its own budget row; the CSV is the source of truth, so a new
    /// team is created on first use and deleting its row resets it. Every device
    /// that sends the same team name shares that team's budget.
    pub(crate) fn resolve(&self, team_name: &str) -> Result<Credential, String> {
        if !safe_device_id(team_name) {
            return Err(
                "team name must be 1-128 characters of letters, numbers, dot, underscore, colon, or hyphen"
                    .to_string(),
            );
        }
        Ok(Credential {
            device_id: team_name.to_string(),
            credential_id: credential_id(team_name),
        })
    }

    pub(crate) fn state(&self, credential: &Credential) -> Result<BudgetState, String> {
        self.update(credential, Update::Read)
    }

    pub(crate) fn consume(
        &self,
        credential: &Credential,
        velocity_mps: Option<f32>,
    ) -> Result<BudgetState, String> {
        self.update(credential, Update::Consume(velocity_mps))
    }

    pub(crate) fn refund(&self, credential: &Credential) -> Result<BudgetState, String> {
        self.update(credential, Update::Refund)
    }

    fn update(&self, credential: &Credential, update: Update) -> Result<BudgetState, String> {
        let mut database = self.load()?;
        let now = epoch_nanoseconds();
        // Reading the budget of a team that has never spent a command returns a
        // full, unsaved allowance. Rows are created only when a command is
        // actually consumed, so simply checking a budget (e.g. while a name is
        // still being typed) never litters the CSV with rows.
        if matches!(update, Update::Read) && !database.devices.contains_key(&credential.device_id) {
            return Ok(BudgetState {
                device_id: credential.device_id.clone(),
                credential_id: credential.credential_id.clone(),
                limit: self.limit,
                used: 0,
                remaining: self.limit,
                budget_version: "0".to_string(),
            });
        }
        let record = database
            .devices
            .entry(credential.device_id.clone())
            .or_insert_with(|| DeviceRecord {
                device_id: credential.device_id.clone(),
                used: 0,
                limit: self.limit,
                created_at: now.clone(),
                updated_at: now.clone(),
                last_velocity_mps: None,
                last_applied_at: None,
            });
        record.limit = self.limit;
        record.used = record.used.min(self.limit);
        match update {
            Update::Read => {}
            Update::Consume(velocity_mps) => {
                if record.used >= self.limit {
                    return Err("velocity command budget exhausted".to_string());
                }
                record.used += 1;
                record.updated_at = next_version(&record.updated_at, &now)?;
                if let Some(velocity_mps) = velocity_mps {
                    record.last_velocity_mps = Some(velocity_mps);
                }
                record.last_applied_at = Some(now);
            }
            Update::Refund => {
                record.used = record.used.saturating_sub(1);
                record.updated_at = next_version(&record.updated_at, &now)?;
            }
        }
        let state = BudgetState {
            device_id: credential.device_id.clone(),
            credential_id: credential.credential_id.clone(),
            limit: self.limit,
            used: record.used,
            remaining: self.limit.saturating_sub(record.used),
            budget_version: record.updated_at.clone(),
        };
        self.save(&database)?;
        Ok(state)
    }

    fn load(&self) -> Result<BudgetDatabase, String> {
        if self.csv_path.exists() {
            return self.load_csv();
        }
        if self.json_path.exists() {
            return Err(format!(
                "authoritative velocity budget CSV {} is missing while JSON mirror exists",
                self.csv_path.display()
            ));
        }
        Ok(BudgetDatabase::default())
    }

    fn load_csv(&self) -> Result<BudgetDatabase, String> {
        let contents = fs::read_to_string(&self.csv_path).map_err(|error| {
            format!(
                "read velocity budget CSV {}: {error}",
                self.csv_path.display()
            )
        })?;
        if !contents.starts_with(CSV_HEADER) {
            return Err("velocity budget CSV is empty or has an invalid header".to_string());
        }
        let mut lines = contents.lines();
        let _ = lines.next();
        let mut devices = HashMap::new();
        for (index, line) in lines.enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let fields = line.split(',').collect::<Vec<_>>();
            if fields.len() != 7 || !safe_device_id(fields[0]) {
                return Err(format!("invalid velocity budget CSV row {}", index + 2));
            }
            let used = fields[1]
                .parse::<u32>()
                .map_err(|_| format!("invalid used count in CSV row {}", index + 2))?;
            let last_velocity_mps = parse_optional_f32(fields[5], index + 2)?;
            validate_version(fields[4], index + 2)?;
            let device_id = fields[0].to_string();
            if devices.contains_key(&device_id) {
                return Err(format!(
                    "duplicate device id in velocity budget CSV row {}",
                    index + 2
                ));
            }
            devices.insert(
                device_id.clone(),
                DeviceRecord {
                    device_id,
                    used: used.min(self.limit),
                    limit: self.limit,
                    created_at: fields[3].to_string(),
                    updated_at: fields[4].to_string(),
                    last_velocity_mps,
                    last_applied_at: optional_string(fields[6]),
                },
            );
        }
        Ok(BudgetDatabase {
            version: 1,
            devices,
        })
    }

    fn save(&self, database: &BudgetDatabase) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(database)
            .map_err(|error| format!("serialize velocity budget database: {error}"))?;
        let csv = serialize_csv(database);
        atomic_write(&self.json_path, &json)?;
        atomic_write(&self.csv_path, csv.as_bytes())
    }
}

#[derive(Clone, Copy, Debug)]
enum Update {
    Read,
    Consume(Option<f32>),
    Refund,
}

pub(crate) fn credential_id(team_name: &str) -> String {
    name_hash(team_name)[..16].to_string()
}

fn name_hash(team_name: &str) -> String {
    let digest = Sha256::digest(team_name.as_bytes());
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn serialize_csv(database: &BudgetDatabase) -> String {
    let mut records = database.devices.values().collect::<Vec<_>>();
    records.sort_by(|left, right| left.device_id.cmp(&right.device_id));
    let mut output = String::from(CSV_HEADER);
    for record in records {
        use std::fmt::Write as _;
        let velocity = record
            .last_velocity_mps
            .map(|value| value.to_string())
            .unwrap_or_default();
        let applied = record.last_applied_at.as_deref().unwrap_or("");
        let _ = writeln!(
            output,
            "{},{},{},{},{},{},{}",
            record.device_id,
            record.used,
            record.limit,
            record.created_at,
            record.updated_at,
            velocity,
            applied
        );
    }
    output
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "create velocity budget directory {}: {error}",
            parent.display()
        )
    })?;
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("velocity-budget");
    let temporary = parent.join(format!(".{filename}.{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = fs::File::create(&temporary)
            .map_err(|error| format!("create {}: {error}", temporary.display()))?;
        file.write_all(bytes)
            .map_err(|error| format!("write {}: {error}", temporary.display()))?;
        file.sync_all()
            .map_err(|error| format!("sync {}: {error}", temporary.display()))?;
        fs::rename(&temporary, path)
            .map_err(|error| format!("replace velocity budget file {}: {error}", path.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn parse_optional_f32(value: &str, row: usize) -> Result<Option<f32>, String> {
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse::<f32>()
        .map(Some)
        .map_err(|_| format!("invalid velocity in CSV row {row}"))
}

fn optional_string(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}

fn next_version(previous: &str, now: &str) -> Result<String, String> {
    let previous = previous
        .parse::<u128>()
        .map_err(|_| "velocity budget updated_at is not an epoch-nanosecond version".to_string())?;
    let now = now
        .parse::<u128>()
        .expect("generated epoch nanoseconds are decimal");
    let successor = previous
        .checked_add(1)
        .ok_or_else(|| "velocity budget version is exhausted".to_string())?;
    Ok(now.max(successor).to_string())
}

fn validate_version(value: &str, row: usize) -> Result<(), String> {
    value
        .parse::<u128>()
        .map(|_| ())
        .map_err(|_| format!("invalid updated_at version in CSV row {row}"))
}

pub(crate) fn safe_device_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

const fn version_one() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::{credential_id, Credential, VelocityBudgetStore};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn credential_id_is_a_stable_16_hex_prefix_of_the_team_name_hash() {
        let id = credential_id("team-alpha");
        assert_eq!(id.len(), 16);
        assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(id, credential_id("team-alpha"));
        assert_ne!(id, credential_id("team-beta"));
    }

    #[test]
    fn refund_is_persisted_to_the_authoritative_csv() {
        let directory = std::env::temp_dir().join(format!(
            "electrode-velocity-refund-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let credential = Credential {
            device_id: "device:refund".to_string(),
            credential_id: "0123456789abcdef".to_string(),
        };
        let store = VelocityBudgetStore::new(
            directory.join("budget.json"),
            directory.join("budget.csv"),
            5,
        );
        let consumed = store.consume(&credential, Some(2.0)).unwrap();
        let consumed_version = consumed.budget_version.parse::<u128>().unwrap();
        assert_eq!(consumed.used, 1);
        let read_version = store
            .state(&credential)
            .unwrap()
            .budget_version
            .parse::<u128>()
            .unwrap();
        assert_eq!(read_version, consumed_version);
        let consumed_again = store.consume(&credential, Some(2.5)).unwrap();
        let second_version = consumed_again.budget_version.parse::<u128>().unwrap();
        assert!(
            second_version > consumed_version,
            "each consume must advance the persisted version"
        );
        drop(store);
        let restarted = VelocityBudgetStore::new(
            directory.join("budget.json"),
            directory.join("budget.csv"),
            5,
        );
        let refunded = restarted.refund(&credential).unwrap();
        assert_eq!(refunded.used, 1);
        assert!(
            refunded.budget_version.parse::<u128>().unwrap() > second_version,
            "refund must advance the persisted version"
        );
        assert_eq!(restarted.state(&credential).unwrap().remaining, 4);
        fs::remove_dir_all(directory).unwrap();
    }
}

fn epoch_nanoseconds() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_string()
}
