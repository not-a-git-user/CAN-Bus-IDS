# CAN Bus Security Lab

> Important
> This repository is only one part of a larger internal project developed for CIEM, the EV department of Manipal Institute of Technology Bangalore.
> The full project also includes a dashboard, packet tracer components, secure communications between the EV and a central hub, AI-based detectors, and a honeypot.
> This is not the final project version, and the complete system is intentionally not published online because doing so would create unnecessary security risk.

> README made using AI 

A small Python lab for simulating normal CAN traffic, generating rogue traffic, detecting suspicious activity, and optionally encrypting log and Redis outputs.

This project is built around a Linux `socketcan` virtual CAN interface (`vcan0`) and is useful for demos, classroom exercises, and local security experiments.

## Features

- Simulates authorized sensor nodes from a JSON telemetry profile
- Generates multiple rogue/attack traffic patterns
- Detects:
  - unauthorized IDs
  - replayed timestamps
  - flooding / bus-war timing
  - missing-slot / timeout timing
  - out-of-range values
  - pinned / deviation values
  - clock skew, drift, and jitter anomalies
- Writes logs to local JSON Lines files
- Optionally publishes alerts and nominal telemetry to Redis
- Supports encrypted log/Redis payloads plus offline decryption helpers

## Project Layout

```text
.
├── authorized_nodes.py
├── unauthorized_node.py
├── detector.py
├── crypto_utils.py
├── decrypt_json.py
├── decrypt_redis.py
├── telemetry_full_standardized.json
├── alerts_live.json
└── sent_logs/
```

## Requirements

- Python 3.10+
- Linux with SocketCAN support
- A `vcan0` interface
- Redis server only if you want live pub/sub output

Python dependencies are listed in `requirements.txt`.

## Installation

```bash
git clone <your-repo-url>
cd canBus
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Set Up `vcan0`

Create a virtual CAN interface before running the scripts:

```bash
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```

To verify:

```bash
ip link show vcan0
```

## Quick Start

Open 2-3 terminals in the project directory.

### 1. Start the detector

```bash
python3 detector.py --verbose
```

### 2. Start authorized traffic

```bash
python3 authorized_nodes.py
```

### 3. Launch an attack

Example:

```bash
python3 unauthorized_node.py --flood
```

You should see normal traffic in the sender terminal and alerts in the detector terminal.

## Telemetry Profile

The file `telemetry_full_standardized.json` defines the allowed CAN IDs, sensor names, expected intervals, and value limits.

Each entry looks like:

```json
{
  "id": "0x302",
  "name": "Speed_mps",
  "interval": 0.92,
  "limits": [0.0, 8.662]
}
```

## Usage

### Authorized Node Sender

Generates nominal sensor traffic from the telemetry profile.

```bash
python3 authorized_nodes.py --input_file telemetry_full_standardized.json
```

Options:

- `--input_file`: telemetry profile JSON
- `--encrypt`: encrypt log lines
- `--encrypt_key`: encryption key, or use `CAN_ENCRYPTION_KEY`

Output:

- Writes JSONL logs to `sent_logs/log_<timestamp>.json`

### Rogue / Attack Sender

Generates rogue traffic and attack patterns.

```bash
python3 unauthorized_node.py --unauth_id
python3 unauthorized_node.py --flood
python3 unauthorized_node.py --inject
python3 unauthorized_node.py --bad_data
python3 unauthorized_node.py --deviation
python3 unauthorized_node.py --replay
python3 unauthorized_node.py --skew
python3 unauthorized_node.py --fingerprint
```

Options:

- `--input_file`: telemetry profile JSON
- `--encrypt`: encrypt rogue log lines
- `--encrypt_key`: encryption key, or use `CAN_ENCRYPTION_KEY`

Output:

- Writes JSONL logs to `sent_logs/log_rogue_<timestamp>.json`

### Detector

Monitors `vcan0`, applies detection rules, writes alerts, and can optionally publish to Redis.

```bash
python3 detector.py --verbose
python3 detector.py --redis
python3 detector.py --redis --encrypt --encrypt_key "secret"
```

Options:

- `--input_file`: telemetry profile JSON
- `--verbose`: print nominal traffic to the console
- `--redis`: publish live output to Redis
- `--encrypt`: encrypt alert logs and Redis payloads
- `--encrypt_key`: encryption key, or use `CAN_ENCRYPTION_KEY`

Output:

- Writes alerts to `alerts_live.json`
- Publishes Redis messages only when `--redis` is enabled

## Redis Channels

When Redis publishing is enabled in `detector.py`, the detector uses:

- `alerts` or `alerts_encrypted`
- `telemetry` or `telemetry_encrypted`

Redis is used by the detector only. The sender scripts write files locally and do not publish to Redis.

## Encryption

To enable encryption, either:

- pass `--encrypt --encrypt_key "<key>"`, or
- export `CAN_ENCRYPTION_KEY`

Example:

```bash
export CAN_ENCRYPTION_KEY="secret-key"
python3 authorized_nodes.py --encrypt
python3 detector.py --redis --encrypt
```

Notes:

- Encryption applies to log lines and Redis payloads
- The raw CAN frames on `vcan0` are not encrypted
- Encrypted logs are still stored as one JSON object per line

## Decryption Helpers

### Decrypt JSONL logs

```bash
python3 decrypt_json.py --input_file alerts_live.json --key "secret-key" --pretty
```

Optional output file:

```bash
python3 decrypt_json.py \
  --input_file sent_logs/log_2026-02-01_20-04-19.json \
  --output_file decrypted.jsonl \
  --key "secret-key"
```

If decryption fails for a line, the script prints an `ALERT` message to stderr and continues.

### Read and decrypt Redis messages

```bash
python3 decrypt_redis.py --key "secret-key"
```

Custom channels:

```bash
python3 decrypt_redis.py --channels alerts_encrypted,telemetry_encrypted --key "secret-key"
```

If a Redis payload cannot be decrypted, the script prints an `ALERT` message to stderr.

## Log Format

The log files use JSON Lines format, not a single JSON array.

That means each line is an independent JSON object:

```json
{"timestamp": 1769956088.5542712, "type": "UNAUTHORIZED_NODE", "id": "0x0", "data_value": -6.250930309295654, "extra": null}
```

This makes the files easy to append to and stream-process.

## Typical Workflow

1. Bring up `vcan0`
2. Start `detector.py`
3. Start `authorized_nodes.py`
4. Start `unauthorized_node.py` with one attack mode
5. Inspect:
   - terminal output
   - `alerts_live.json`
   - `sent_logs/`
   - Redis channels, if enabled
6. Decrypt logs later if encryption was enabled

## Limitations

- Designed for Linux `socketcan` with `vcan0`
- No web UI or dashboard
- Uses local files and optional local Redis only
- Log files are append-only JSONL
- The project focuses on simulation and lab experiments, not production-grade CAN hardening
- CAN payloads themselves are not encrypted on the bus

## Troubleshooting

### `Can't bind to vcan0 interface`

Make sure `vcan0` exists and is up:

```bash
ip link show vcan0
```

### Redis connection errors

Start Redis locally:

```bash
redis-server
```

### Encryption enabled but no key provided

Set a key explicitly:

```bash
export CAN_ENCRYPTION_KEY="secret-key"
```

or pass one on the command line:

```bash
python3 detector.py --encrypt --encrypt_key "secret-key"
```

## License

Add a license file if you plan to publish this repository publicly.
