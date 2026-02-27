#!/usr/bin/env python3
import base64
import random
from kv_test_framework.test_framework import KVTestFramework
from utility.kv import (
    MAX_U64,
    MAX_STREAM_ID,
    to_stream_id,
    create_kv_data,
    rand_write,
)
from utility.submission import submit_data
from kv_utility.submission import create_submission
from utility.utils import (
    assert_equal,
    wait_until,
)
from config.node_config import TX_PARAMS, TX_PARAMS1, GENESIS_ACCOUNT, GENESIS_ACCOUNT1


class KVPutGetTest(KVTestFramework):
    def setup_params(self):
        self.num_blockchain_nodes = 1
        self.num_nodes = 1

    def run_test(self):
        # setup kv node, watch stream with id [0,100)
        self.stream_ids = [to_stream_id(i) for i in range(MAX_STREAM_ID)]
        self.stream_ids.reverse()
        self.setup_kv_node(0, self.stream_ids)
        self.stream_ids.reverse()
        assert_equal(
            [x[2:] for x in self.kv_nodes[0].kv_get_holding_stream_ids()],
            self.stream_ids,
        )

        # tx_seq and data mapping
        self.next_tx_seq = 0
        self.data = {}
        # write empty stream
        self.write_streams()

        # rpc edge case tests
        self.test_len_zero()
        self.test_len_one()
        self.test_len_larger_than_value()
        self.test_start_index_at_boundary()
        self.test_nonexistent_key()

    def submit(
        self,
        version,
        reads,
        writes,
        access_controls,
        tx_params=TX_PARAMS,
        given_tags=None,
        trunc=False,
    ):
        chunk_data, tags = create_kv_data(version, reads, writes, access_controls)
        if trunc:
            chunk_data = chunk_data[
                : random.randrange(len(chunk_data) // 2, len(chunk_data))
            ]
        submissions, data_root = create_submission(
            chunk_data, tags if given_tags is None else given_tags
        )
        self.contract.submit(submissions, tx_prarams=tx_params)
        wait_until(lambda: self.contract.num_submissions() == self.next_tx_seq + 1)

        client = self.nodes[0]
        wait_until(lambda: client.zgs_get_file_info(data_root) is not None)

        segments = submit_data(client, chunk_data)
        wait_until(lambda: client.zgs_get_file_info(data_root)["finalized"])

    def update_data(self, writes):
        for write in writes:
            self.data[",".join([write[0], write[1]])] = (
                write[3] if len(write[3]) > 0 else None
            )

    def write_streams(self):
        # first put
        stream_id = to_stream_id(1)
        writes = [rand_write(stream_id) for i in range(20)]
        self.submit(MAX_U64, [], writes, [])
        wait_until(
            lambda: self.kv_nodes[0].kv_get_trasanction_result(self.next_tx_seq)
            == "Commit"
        )
        first_version = self.next_tx_seq
        self.next_tx_seq += 1

        # check data and admin role
        self.update_data(writes)
        for stream_id_key, value in self.data.items():
            stream_id, key = stream_id_key.split(",")
            self.kv_nodes[0].check_equal(stream_id, key, value)
            assert_equal(
                self.kv_nodes[0].kv_is_admin(GENESIS_ACCOUNT.address, stream_id), True
            )

        # iterate
        pair = self.kv_nodes[0].seek_to_first(stream_id)
        current_key = None
        cnt = 0
        deleted = 0
        writes = []
        while pair != None:
            cnt += 1
            if current_key is not None:
                assert current_key < pair["key"]
            current_key = pair["key"]
            tmp = ",".join([stream_id, pair["key"]])
            assert tmp in self.data
            value = self.data[tmp]
            assert_equal(value, pair["data"])
            if cnt % 3 != 0:
                writes.append(rand_write(stream_id, pair["key"], 0))
                deleted += 1

            pair = self.kv_nodes[0].next(stream_id, current_key)
        assert cnt == len(self.data.items())

        # iterate(reverse)
        pair = self.kv_nodes[0].seek_to_last(stream_id)
        current_key = None
        cnt = 0
        while pair != None:
            cnt += 1
            if current_key is not None:
                assert current_key > pair["key"]
            current_key = pair["key"]
            tmp = ",".join([stream_id, pair["key"]])
            assert tmp in self.data
            value = self.data[tmp]
            assert_equal(value, pair["data"])

            pair = self.kv_nodes[0].prev(stream_id, current_key)
        assert cnt == len(self.data.items())

        # delete
        self.submit(MAX_U64, [], writes, [])
        wait_until(
            lambda: self.kv_nodes[0].kv_get_trasanction_result(self.next_tx_seq)
            == "Commit"
        )
        second_version = self.next_tx_seq
        self.next_tx_seq += 1

        # iterate at first version
        pair = self.kv_nodes[0].seek_to_first(stream_id, first_version)
        current_key = None
        cnt = 0
        while pair != None:
            cnt += 1
            if current_key is not None:
                assert current_key < pair["key"]
            current_key = pair["key"]
            tmp = ",".join([stream_id, pair["key"]])
            assert tmp in self.data
            value = self.data[tmp]
            assert_equal(value, pair["data"])

            pair = self.kv_nodes[0].next(stream_id, current_key, first_version)
        assert cnt == len(self.data.items())

        pair = self.kv_nodes[0].seek_to_last(stream_id, first_version)
        current_key = None
        cnt = 0
        while pair != None:
            cnt += 1
            if current_key is not None:
                assert current_key > pair["key"]
            current_key = pair["key"]
            tmp = ",".join([stream_id, pair["key"]])
            assert tmp in self.data
            value = self.data[tmp]
            assert_equal(value, pair["data"])

            pair = self.kv_nodes[0].prev(stream_id, current_key, first_version)
        assert cnt == len(self.data.items())

        # iterate at second version
        pair = self.kv_nodes[0].seek_to_first(stream_id, second_version)
        current_key = None
        cnt = 0
        while pair != None:
            cnt += 1
            if current_key is not None:
                assert current_key < pair["key"]
            current_key = pair["key"]
            tmp = ",".join([stream_id, pair["key"]])
            assert tmp in self.data
            value = self.data[tmp]
            assert_equal(value, pair["data"])

            pair = self.kv_nodes[0].next(stream_id, current_key, second_version)
        assert cnt == len(self.data.items()) - deleted

        pair = self.kv_nodes[0].seek_to_last(stream_id, second_version)
        current_key = None
        cnt = 0
        while pair != None:
            cnt += 1
            if current_key is not None:
                assert current_key > pair["key"]
            current_key = pair["key"]
            tmp = ",".join([stream_id, pair["key"]])
            assert tmp in self.data
            value = self.data[tmp]
            assert_equal(value, pair["data"])

            pair = self.kv_nodes[0].prev(stream_id, current_key, second_version)
        assert cnt == len(self.data.items()) - deleted

        self.update_data(writes)

    def _get_first_key_and_value(self):
        """Get the first non-deleted key and its value from self.data."""
        stream_id = to_stream_id(1)
        for stream_id_key, value in sorted(self.data.items()):
            sid, key = stream_id_key.split(",")
            if sid == stream_id and value is not None:
                return stream_id, key, value
        raise AssertionError("no non-deleted key found")

    def test_len_zero(self):
        """len=0 should return metadata with empty data, not crash."""
        stream_id, key, value = self._get_first_key_and_value()
        node = self.kv_nodes[0]

        # kv_getValue with len=0
        res = node.kv_get_value(stream_id, key, 0, 0)
        assert res is not None, "kv_getValue(len=0) returned None"
        assert_equal(base64.b64decode(res["data"].encode("utf-8")), b"")
        assert_equal(res["size"], len(value))

        # kv_getFirst with len=0
        res = node.kv_get_first(stream_id, 0, 0)
        assert res is not None, "kv_getFirst(len=0) returned None"
        assert_equal(base64.b64decode(res["data"].encode("utf-8")), b"")
        assert res["size"] > 0

        # kv_getLast with len=0
        res = node.kv_get_last(stream_id, 0, 0)
        assert res is not None, "kv_getLast(len=0) returned None"
        assert_equal(base64.b64decode(res["data"].encode("utf-8")), b"")
        assert res["size"] > 0

        # kv_getNext with len=0
        res = node.kv_get_next(stream_id, key, 0, 0)
        assert res is not None, "kv_getNext(len=0) returned None"
        assert_equal(base64.b64decode(res["data"].encode("utf-8")), b"")
        assert res["size"] > 0

        # kv_getPrev with len=0 (use last key so there's a prev)
        last_pair = node.seek_to_last(stream_id)
        res = node.kv_get_prev(stream_id, last_pair["key"], 0, 0)
        assert res is not None, "kv_getPrev(len=0) returned None"
        assert_equal(base64.b64decode(res["data"].encode("utf-8")), b"")
        assert res["size"] > 0

    def test_len_one(self):
        """len=1 should return exactly 1 byte of data."""
        stream_id, key, value = self._get_first_key_and_value()
        node = self.kv_nodes[0]

        res = node.kv_get_value(stream_id, key, 0, 1)
        assert res is not None
        data = base64.b64decode(res["data"].encode("utf-8"))
        assert_equal(len(data), 1)
        assert_equal(data, value[:1])
        assert_equal(res["size"], len(value))

        res = node.kv_get_first(stream_id, 0, 1)
        assert res is not None
        data = base64.b64decode(res["data"].encode("utf-8"))
        assert_equal(len(data), 1)

    def test_len_larger_than_value(self):
        """len larger than remaining bytes should return clamped data."""
        stream_id, key, value = self._get_first_key_and_value()
        node = self.kv_nodes[0]

        # read from midpoint with len larger than remaining bytes
        mid = len(value) // 2
        remaining = len(value) - mid
        oversized_len = remaining + 1024
        res = node.kv_get_value(stream_id, key, mid, oversized_len)
        assert res is not None
        data = base64.b64decode(res["data"].encode("utf-8"))
        assert_equal(data, value[mid:])
        assert_equal(res["size"], len(value))

    def test_start_index_at_boundary(self):
        """start_index at or past value size should return error."""
        stream_id, key, value = self._get_first_key_and_value()
        node = self.kv_nodes[0]

        try:
            node.kv_get_value(stream_id, key, len(value) + 1, 1)
            assert False, "expected error for start_index past value size"
        except Exception:
            pass

    def test_nonexistent_key(self):
        """Querying a key that doesn't exist should return empty."""
        stream_id = to_stream_id(1)
        node = self.kv_nodes[0]
        fake_key = "ff" * 32  # key that was never written

        res = node.kv_get_value(stream_id, fake_key, 0, 1)
        assert res is not None
        assert_equal(base64.b64decode(res["data"].encode("utf-8")), b"")
        assert_equal(res["size"], 0)


if __name__ == "__main__":
    KVPutGetTest().main()
