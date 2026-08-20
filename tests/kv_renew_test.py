#!/usr/bin/env python3
from kv_test_framework.test_framework import KVTestFramework
from utility.kv import MAX_U64, to_stream_id, create_kv_data, rand_write
from utility.submission import submit_data
from kv_utility.submission import create_submission
from utility.utils import assert_equal, wait_until
from config.node_config import TX_PARAMS, TX_PARAMS1, GENESIS_ACCOUNT, GENESIS_ACCOUNT1

# Everything is "stale" the instant it lands, so the renewer sweeps every key
# on its very first cycle instead of waiting out a real max-age window.
RENEW_MAX_AGE_SECS = 1
# The service waits at most one cycle interval for a renewal to replay before
# recording the outcome, so this doubles as the verification window. Keep it
# comfortably above the devnet's submit-to-replay latency (a few seconds):
# too short and the renewal lands *after* the check that would have counted
# it, leaving `keysRenewed` at 0 even though the write went through.
RENEW_CYCLE_INTERVAL_SECS = 15
RENEW_STARTUP_DELAY_SECS = 1
RENEW_PAUSE_BETWEEN_BATCHES_MS = 100


class KVRenewTest(KVTestFramework):
    def setup_params(self):
        self.num_blockchain_nodes = 1
        self.num_nodes = 1

    def run_test(self):
        renew_stream_id = to_stream_id(0)
        # A second stream first written by a *different* account: that
        # account becomes its admin, so the renew signer (GENESIS_ACCOUNT)
        # has no write permission there and its keys must be skipped rather
        # than renewed.
        skip_stream_id = to_stream_id(1)

        self.setup_kv_node(
            0,
            [renew_stream_id, skip_stream_id],
            updated_config={
                "zgs_node_urls": ",".join([node.rpc_url for node in self.nodes]),
                "renew_private_key": GENESIS_ACCOUNT.key.hex(),
                "renew_max_age_secs": RENEW_MAX_AGE_SECS,
                "renew_cycle_interval_secs": RENEW_CYCLE_INTERVAL_SECS,
                "renew_startup_delay_secs": RENEW_STARTUP_DELAY_SECS,
                "renew_pause_between_batches_ms": RENEW_PAUSE_BETWEEN_BATCHES_MS,
            },
        )
        kv = self.kv_nodes[0]

        # 1. Write one key through the normal path. The genesis account is
        #    the first (and so far only) writer of `renew_stream_id`, which
        #    makes it that stream's admin -- and the admin is exactly who
        #    we configured as the renew signer, so its keys are never
        #    permission-skipped.
        key_hex, value, v0 = self.write_and_commit(renew_stream_id, TX_PARAMS)
        assert_equal(kv.kv_is_admin(GENESIS_ACCOUNT.address, renew_stream_id), True)

        # 2. Seed the permission-skip stream: GENESIS_ACCOUNT1 writes first,
        #    so it -- not the renew signer -- becomes admin there.
        skip_key_hex, skip_value, skip_v0 = self.write_and_commit(
            skip_stream_id, TX_PARAMS1
        )
        assert_equal(kv.kv_is_admin(GENESIS_ACCOUNT1.address, skip_stream_id), True)
        assert_equal(kv.kv_is_admin(GENESIS_ACCOUNT.address, skip_stream_id), False)

        # 3. Give the renewer time to notice both streams are stale, drain
        #    `renew_stream_id`, re-upload it, and have this node replay the
        #    renewal transaction: `version` must advance past the original.
        wait_until(
            lambda: kv.kv_get_value(renew_stream_id, key_hex, 0, len(value))["version"]
            > v0,
            timeout=180,
        )

        # 4. Status reflects the work: at least one key renewed, at least
        #    one key skipped for lack of permission (the other stream, every
        #    cycle it's rescanned), and nothing stuck.
        #
        #    The counters are published as each cycle finishes its work, so
        #    they trail the replayed version observed in step 3 -- poll rather
        #    than sampling once.
        def counters_published():
            s = kv.rpc.kv_getRenewStatus()
            return s["keysRenewed"] >= 1 and s["keysSkippedPermission"] >= 1

        wait_until(counters_published, timeout=180)
        status = kv.rpc.kv_getRenewStatus()
        self.log.info("renew status: %s", status)
        assert_equal(len(status["stuckKeys"]), 0)

        # 5. The permission-skipped key must not have been touched at all.
        skip_now = kv.kv_get_value(skip_stream_id, skip_key_hex, 0, len(skip_value))
        assert_equal(skip_now["version"], skip_v0)

    def write_and_commit(self, stream_id, tx_params):
        """Write one random key/value into `stream_id` from `tx_params`'s
        sender, wait for this node to replay it, and return
        (key_hex, value, version)."""
        kv = self.kv_nodes[0]
        writes = [rand_write(stream_id, size=32)]
        chunk_data, tags = create_kv_data(MAX_U64, [], writes, [])
        submissions, data_root = create_submission(
            chunk_data, tags, tx_params["from"]
        )
        self.contract.submit(submissions, tx_prarams=tx_params)

        # The renewal service submits to the same Flow contract on its own
        # schedule, so neither the contract's total submission count nor a
        # locally incremented counter identifies *this* write's transaction:
        # both txs can even land in the same block. Read the sequence number
        # back off the storage node instead.
        client = self.nodes[0]
        wait_until(lambda: client.zgs_get_file_info(data_root) is not None)
        tx_seq = client.zgs_get_file_info(data_root)["tx"]["seq"]
        submit_data(client, chunk_data)
        wait_until(lambda: client.zgs_get_file_info(data_root)["finalized"])

        wait_until(lambda: kv.kv_get_trasanction_result(tx_seq) == "Commit")

        key_hex, value = writes[0][1], writes[0][3]
        version = kv.kv_get_value(stream_id, key_hex, 0, len(value))["version"]
        return key_hex, value, version


if __name__ == "__main__":
    KVRenewTest().main()
