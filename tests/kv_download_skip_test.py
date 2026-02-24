#!/usr/bin/env python3
from kv_test_framework.test_framework import KVTestFramework
from utility.kv import (
    MAX_U64,
    to_stream_id,
    create_kv_data,
    rand_write,
)
from utility.submission import submit_data
from kv_utility.submission import create_submission
from utility.utils import (
    wait_until,
)
from config.node_config import TX_PARAMS


class KVDownloadSkipTest(KVTestFramework):
    """Test that a KV node skips undownloadable transactions after retries.

    Submits a tx to blockchain WITHOUT uploading file data, verifying the KV
    node eventually marks it as DownloadFailed and continues processing
    subsequent transactions.
    """

    def setup_params(self):
        self.num_blockchain_nodes = 1
        self.num_nodes = 1
        self.zgs_node_configs[0] = {
            "db_max_num_sectors": 2 ** 30,
        }

    def run_test(self):
        stream_id = to_stream_id(0)

        # Setup KV node with small retry settings so the test finishes quickly.
        # max_download_retries=2: skip after 2 consecutive sync_data failures
        # download_timeout_ms=30000: 30s timeout for waiting for file locations
        # download_retry_interval_ms=1000: 1s sleep between retries
        self.setup_kv_node(0, [stream_id], updated_config={
            "zgs_node_urls": self.nodes[0].rpc_url,
            "max_download_retries": 2,
            "download_timeout_ms": 30000,
            "download_retry_interval_ms": 1000,
        })
        self.next_tx_seq = 0

        # Step 1: Normal tx with file upload — should commit
        first_writes = self.submit_normal_tx(stream_id)

        # Step 2: Tx without file upload — should be skipped
        self.submit_without_upload(stream_id)

        # Step 3: Another normal tx — should commit, proving the system moved on
        second_writes = self.submit_normal_tx(stream_id)

        # Verify data from both successful txs is still correct
        for w in first_writes:
            self.kv_nodes[0].check_equal(w[0], w[1], w[3])
        for w in second_writes:
            self.kv_nodes[0].check_equal(w[0], w[1], w[3])

    def submit_normal_tx(self, stream_id):
        """Submit a tx with file upload. Returns the writes list."""
        writes = [rand_write(stream_id=stream_id, size=100)]
        chunk_data, tags = create_kv_data(MAX_U64, [], writes, [])
        submissions, data_root = create_submission(chunk_data, tags)
        self.contract.submit(submissions, tx_prarams=TX_PARAMS)
        wait_until(
            lambda: self.contract.num_submissions() == self.next_tx_seq + 1
        )

        # Upload file data to storage node
        wait_until(
            lambda: self.nodes[0].zgs_get_file_info(data_root) is not None
        )
        submit_data(self.nodes[0], chunk_data)
        wait_until(
            lambda: self.nodes[0].zgs_get_file_info(data_root)["finalized"]
        )

        # Wait for KV node to process
        wait_until(
            lambda: self.kv_nodes[0].kv_get_trasanction_result(self.next_tx_seq)
            == "Commit",
            timeout=60,
        )
        self.log.info("tx %d committed successfully", self.next_tx_seq)
        self.next_tx_seq += 1
        return writes

    def submit_without_upload(self, stream_id):
        """Submit a tx but don't upload file data. Should be skipped."""
        writes = [rand_write(stream_id=stream_id, size=100)]
        chunk_data, tags = create_kv_data(MAX_U64, [], writes, [])
        submissions, data_root = create_submission(chunk_data, tags)
        self.contract.submit(submissions, tx_prarams=TX_PARAMS)
        wait_until(
            lambda: self.contract.num_submissions() == self.next_tx_seq + 1
        )

        # DO NOT upload file data — simulates an unavailable file.
        # The KV node should skip this tx after max_download_retries failures.
        wait_until(
            lambda: self.kv_nodes[0].kv_get_trasanction_result(self.next_tx_seq)
            == "DownloadFailed",
            timeout=180,
        )
        self.log.info(
            "tx %d correctly skipped as DownloadFailed", self.next_tx_seq
        )
        self.next_tx_seq += 1


if __name__ == "__main__":
    KVDownloadSkipTest().main()
