# Electrode command authority

This crate is the security boundary between browser Zenoh peers and native
vehicle peers. It opens separate WebSocket and UDP sessions with multicast
discovery disabled. Nothing crosses from the browser session to the vehicle
session unless an explicit mapping in `CommandPolicy` accepts it.

Accepted typed intents:

- `gcs/v1/cmd/velocity` -> `synapse/v1/topic/local_position_command`
- `gcs/v1/cmd/manual` -> `synapse/v1/topic/manual_control_command`
- `gcs/v1/cmd/radio` -> `synapse/v1/topic/radio_control`
- `gcs/v1/cmd/gain` -> `synapse/v1/cmd/param_set` query

`gcs/v1/cmd/raw/<leaf>` preserves the Packet Traffic prototype feature. The
leaf must be one safe segment and each payload is bounded to 4 KiB. Explicitly
selected typed leaves are allowed; the bytes are forwarded exactly and are not
claimed to be a schema-verified FlatBuffer. Repeat and interval are controlled
by the website.

Vehicle telemetry is relayed one way to the browser. The only non-command
browser-to-vehicle relay is the schema-verified private Rumoca `MocapFrame`.

## Firmware updates

The browser's staged namespace is
`gcs/v1/cmd/firmware/<update-id>/{start,chunk/<index>,commit}`. The vehicle-side
query keys are `synapse/v1/cmd/firmware_{info,status,prepare,chunk,commit,abort}`.
Published `synapse_fbs` 0.5.0 does not export these generated request/reply
types. Until the additive schema release lands, this crate uses bounded
low-level FlatBuffer readers/builders for those exact table layouts. It
assembles and hashes the browser upload, compares it with a trusted baseline,
allows differences only inside configured gain windows, and only then performs
the vehicle query transfer with chunk retries. Progress is published on
`gcs/v1/status/firmware/<update-id>`.

Set `ELECTRODE_GCS_FIRMWARE_BASELINE` to the trusted binary and
`ELECTRODE_GCS_GAIN_WINDOWS_PATH` to the gain-window JSON. The CUBS2 prototype
artifact paths are detected when present. First-upload baseline bootstrapping
is disabled unless `ELECTRODE_GCS_FIRMWARE_AUTOBOOTSTRAP=true` is explicitly
set.
