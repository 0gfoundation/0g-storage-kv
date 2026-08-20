# Storage KV

0G Storage KV is a key-value database abstraction built on top of the 0G storage layer. Files with specific tags uploaded to the storage layer are treated as KV files. Users who wish to use KV can set up a service called KV Node themselves. This service monitors, downloads and deserializes KV files. It then reconstructs the KV database locally by replaying the KV database operations contained in the KV files.

## Hardware Requirement

```
- Memory: 4 GB RAM
- CPU: 2 cores
- Disk: Matches the size of kv streams it maintains
```

## Build

```
cargo build --release
```

## Configuration

Copy the `config_example.toml` to `config.toml` and update the parameters:

```toml
#######################################################################
###                   Key-Value Stream Options                      ###
#######################################################################

# In KV Scenario, each independent KV database abstraction has an unique stream id.

# Streams to monitor.
stream_ids = ["000000000000000000000000000000000000000000000000000000000000f2bd", "000000000000000000000000000000000000000000000000000000000000f009", "0000000000000000000000000000000000000000000000000000000000016879", "0000000000000000000000000000000000000000000000000000000000002e3d"]

#######################################################################
###                     DB Config Options                           ###
#######################################################################

# Directory to store data.
db_dir = "db"
# Directory to store KV Metadata.
kv_db_dir = "kv.DB"

#######################################################################
###                     Log Sync Config Options                     ###
#######################################################################

blockchain_rpc_endpoint = ""
log_contract_address = ""
# log_sync_start_block_number should be earlier than the block number of the first transaction that writes to the stream being monitored.
log_sync_start_block_number = 0

#######################################################################
###                     RPC Config Options                          ###
#######################################################################

# Whether to provide RPC service.
rpc_enabled = true

# HTTP server address to bind for public RPC.
rpc_listen_address = "0.0.0.0:6789"

# Indexer endpoint to fetch storage node locations. Leave empty to use zgs_node_urls instead.
indexer_url = "https://indexer-storage-turbo-testnet.0g.ai"
# Static ZGS node list (used when indexer_url is empty).
zgs_node_urls = ""

#######################################################################
###                     Misc Config Options                         ###
#######################################################################

log_config_file = "log_config"
```

### Run

```bash
cd run

../target/release/zgs_kv --config config.toml
```

## Data Lifetime Renewal

Data stored on the 0G storage layer has a finite lifetime (approximately one year). The KV node includes a background renewal service that periodically re-uploads aging values to extend their lifetime. This keeps the stream's data accessible and its access-control state fresh.

### How It Works

The renewal service runs on a configurable weekly cycle (by default). Each cycle:

1. Scans for keys older than the age threshold (180 days by default).
2. Re-uploads the latest version of each stale key and the stream's current access-control state as a fresh KV file.
3. Verifies that the uploads have taken effect on the chain.

Only the latest version of each key is renewed; older versions remain accessible only while their original files persist. All KV nodes monitoring the stream re-download renewed data, so renewal involves real storage costs.

### Deployment

The renewal signer must be the **stream admin**. The recommended deployment is:

- Run the KV node on a machine controlled by the stream admin.
- Set `renew_private_key` to the admin's private key (or use the `ZGS_KV_RENEW_PRIVATE_KEY` environment variable, which is preferred over the config file).
- Keep only one renewing node per stream — running renewal on two nodes causes both to pay the renewal fees.
- Consider using a single admin account for the stream to keep access control simple and predictable.

The node can grant write access to other users via standard SDK operations; the weekly renewal automatically preserves these grants from then on.

### Configuration

See the [Data Lifetime Renewal Options](#data-lifetime-renewal-options) section in `config_example.toml` for all renewal parameters. Key settings:

- `renew_private_key` — the admin's key (leave empty to disable renewal).
- `renew_enabled` — kill switch (defaults to true if a key is set).
- `renew_max_age_secs` — age threshold (default 180 days).
- `renew_cycle_interval_secs` — cycle frequency (default 7 days).
- `renew_dry_run` — scan and log without uploading (useful for testing on old streams).

### First Run on Existing Streams

When enabling renewal on a stream with existing data:

1. Start with `renew_dry_run = true` to scan for stale keys and estimate the cost without spending funds.
2. Review the logs to understand the scope and cost.
3. Set `renew_dry_run = false` and restart the node to begin actual renewal.

### Monitoring and Control

- `kv_getRenewStatus` (RPC) — returns the last cycle's results: number of keys scanned, renewed, and skipped, total bytes uploaded, any keys stuck past max attempts, and the current ACL renewal status.
- `admin_renewNow` (RPC) — triggers an immediate renewal cycle (requires EIP-712 admin signature).

### IMPORTANT — Role Changes During Renewal

Do not issue role-change operations (grants, revokes, renounces, special-key flips) while a renewal cycle is running — they may be silently overridden by the renewal snapshot. Check `kv_getRenewStatus.aclRenewalInProgress` first, or schedule changes outside the documented cycle time (default weekly).

If a role change does land during a renewal window:

1. The node detects it after replay and logs an ERROR.
2. The conflict is reported in `kv_getRenewStatus` with the affected accounts and keys.
3. You must manually re-issue the change and overwrite any keys written under the wrongly restored permission.

This risk is small in practice when following the deployment model above: the stream admin (who is the only one who can revoke) is also the operator running the node, so changes can be coordinated. Third parties can only grant (safe — the snapshot emits nothing for accounts it did not see) or renounce their own role.

## Data Lifetime Renewal Options
