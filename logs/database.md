# Creating a Database with the Attack Logs

## 1. Overview

This utility is a lightweight Python script designed to parse, deduplicate, and ingest raw Cowrie SSH honeypot logs into a SQLite database. It handles both JSON Cowrie outputs and WalT-prefixed log streams, applying automatic geographical mapping and timezone normalization to standard `UTC+3`.

## 2. Prerequisites & System Requirements

The script uses the Python Standard Library.

* **Python:** Version 3.7 or higher (required for `datetime.fromisoformat` support).
* **Database Engine:** SQLite3 (SQLite3 is built into Python's standard library).

## 3. Configuration

By default, the script looks for three specific log files in the same directory since I am handling three nodes and I keep their logs in separate files. These can be modified by editing the constants at the top of the script:

```python
FILES_TO_PROCESS = [
    "goofy-cowrie.json",
    "pluto-cowrie.json",
    "mickey-cowrie.json"
]
```

Node geographical mappings are pre-configured to append continent data to the node names based on the honeypot's distributed architecture:

* `goofy` $\rightarrow$ America
* `pluto` $\rightarrow$ Europe
* `mickey` $\rightarrow$ Asia

## 4. Execution / Usage

The script can be executed in two different modes.

### A. Default

Running the script without any arguments will automatically target the files defined in the `FILES_TO_PROCESS` list.

```bash
python build_db.py
```

### B. Passing Arguments

You can override the default list and process specific files by passing their filenames as arguments via the terminal.

```bash
python build_db.py goofy-cowrie.json pluto-cowrie.json mickey-cowrie.json
```

## 5. Architectural Features

* **Duplicates:** The script dynamically generates an MD5 cryptographic hash for every raw JSON line (`event_hash`). The database schema enforces a `UNIQUE` constraint on this hash. Combined with SQLite's `INSERT OR IGNORE`, the script can safely re-process the same log files repeatedly without generating duplicate records.
* **Formatting:** Natively strips out `WalT` routing prefixes (e.g., `14:14:35.082296 mickey.cowrie-attacks ->`) before parsing, while remaining compatible with standard, raw Cowrie JSON streams.
* **Indexing:** Automatically generates database indexes (`idx_eventid`, `idx_session`, `idx_src_ip`) upon creation, optimizing the `honeypot.db` file for better querying.

## 6. Database Schema (`honeypot.db`)

The script generates a local SQLite database by creating a table named `events`. It is designed to hold different log types (e.g., logins, command executions, file downloads).

### Table: `events`

| Column Name | Data Type | Description |
| --- | --- | --- |
| **`id`** | `INTEGER` | The primary key. An auto-incrementing internal row identifier. |
| **`event_hash`** | `TEXT` | **(UNIQUE)** An MD5 hash of the raw JSON payload used to strictly prevent duplicate log ingestion. |
| **`timestamp`** | `TEXT` | The time the event occurred, automatically converted to `UTC+3`. |
| **`node`** | `TEXT` | The name of the node that captured the event, paired with geographic metadata (e.g., `mickey (Asia)`). |
| **`eventid`** | `TEXT` | Cowrie's internal classification string for the action (e.g., `cowrie.login.failed`, `cowrie.command.input`). |
| **`session`** | `TEXT` | A unique identifier tying multiple events together into a single attacker SSH session. |
| **`src_ip`** | `TEXT` | The public IP address of the attacker. |
| **`username`** | `TEXT` | The username attempted by the attacker during authentication. |
| **`password`** | `TEXT` | The password attempted by the attacker during authentication. |
| **`input`** | `TEXT` | The keystrokes or terminal commands executed by the attacker once inside the honeypot. |
| **`url`** | `TEXT` | The external web address if the attacker attempts to download a payload via `wget` or `curl`. |
| **`destfile`** | `TEXT` | The local file path where downloaded malware is saved within the honeypot environment. |
| **`shasum`** | `TEXT` | The SHA-256 hash of any files dropped or downloaded by the attacker. |
| **`dst_ip`** | `TEXT` | The destination IP address (typically the internal wireguard IP of the honeypot node itself). |
| **`dst_port`** | `INTEGER` | The destination port targeted by the attacker. |
| **`data`** | `TEXT` | A catch-all column for metadata or extended payloads that don't fit standard fields. |
| **`raw_json`** | `TEXT` | An unmodified, complete backup of the original Cowrie JSON string. |

### Database Indexes

To ensure better performance when querying a huge database, the script automatically builds specific B-Tree indexes on creation:

* **`idx_eventid`**: Indexed on the `eventid` column to speed up aggregation queries (e.g., counting total failed logins vs. successful logins).
* **`idx_session`**: Indexed on the `session` column to allow fast, chronological reconstruction of a single attacker's entire interaction history.
* **`idx_src_ip`**: Indexed on the `src_ip` column for faster filtering of global attacker IP addresses and identifying top offenders.