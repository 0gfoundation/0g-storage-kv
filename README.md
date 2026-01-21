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

# Zerog storage nodes to download data from.
zgs_node_urls = "http://127.0.0.1:5678,http://127.0.0.1:5679"

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
