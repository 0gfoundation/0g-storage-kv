#!/usr/bin/env python3
import random
from kv_test_framework.test_framework import KVTestFramework
from utility.kv import (
    MAX_U64,
    is_access_control_permission_denied,
    is_sender_no_write_permission,
    is_write_permission_denied,
    MAX_STREAM_ID,
    to_stream_id,
    create_kv_data,
    AccessControlOps,
    rand_key,
    rand_write,
)
from utility.submission import submit_data
from kv_utility.submission import create_submission
from utility.utils import (
    assert_equal,
    wait_until,
)
from config.node_config import TX_PARAMS, TX_PARAMS1, GENESIS_ACCOUNT, GENESIS_ACCOUNT1


class KVAccessControlTest(KVTestFramework):
    def setup_params(self):
        self.num_blockchain_nodes = 1
        self.num_nodes = 1

    def run_test(self):
        # setup kv node, watch stream with id [0,100)
        self.stream_ids = [to_stream_id(i) for i in range(MAX_STREAM_ID)]
        self.setup_kv_node(0, self.stream_ids)
        # tx_seq and data mapping
        self.next_tx_seq = 0
        self.data = {}
        self.cross_test(self.stream_ids[0])
        self.revoke_test(self.stream_ids[1])
        self.renounce_admin_test(self.stream_ids[2])

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
                : random.randrange(len(chunk_data) / 2, len(chunk_data))
            ]
        submissions, data_root = create_submission(
            chunk_data, tags if given_tags is None else given_tags, tx_params["from"]
        )
        self.contract.submit(submissions, tx_prarams=tx_params)
        wait_until(lambda: self.contract.num_submissions() == self.next_tx_seq + 1)

        client = self.nodes[0]
        wait_until(lambda: client.zgs_get_file_info(data_root) is not None)

        segments = submit_data(client, chunk_data)
        wait_until(lambda: client.zgs_get_file_info(data_root)["finalized"])

    def update_data(self, writes):
        for write in writes:
            self.data[",".join([write[0], write[1]])] = write[3]

    def renounce_admin_test(self, stream_id):
        assert_equal(
            self.kv_nodes[0].kv_has_write_permission(
                GENESIS_ACCOUNT.address, stream_id, rand_key()
            ),
            True,
        )
        # first put
        writes = [rand_write(stream_id)]
        access_controls = [AccessControlOps.renounce_admin_role(stream_id)]
        # grant writer role
        self.submit(MAX_U64, [], writes, access_controls)
        wait_until(
            lambda: self.kv_nodes[0].kv_get_trasanction_result(self.next_tx_seq)
            == "Commit"
        )
        first_version = self.next_tx_seq
        self.next_tx_seq += 1

        # check data and role
        self.update_data(writes)
        for stream_id_key, value in self.data.items():
            stream_id, key = stream_id_key.split(",")
            self.kv_nodes[0].check_equal(stream_id, key, value, first_version)
        assert_equal(
            self.kv_nodes[0].kv_is_admin(GENESIS_ACCOUNT.address, stream_id), False
        )

    def revoke_test(self, stream_id):
        assert_equal(
            self.kv_nodes[0].kv_has_write_permission(
                GENESIS_ACCOUNT.address, stream_id, rand_key()
            ),
            True,
        )
        special_key = rand_key()
        # first put
        writes = [rand_write(stream_id), rand_write(stream_id, special_key)]
        access_controls = []
        # grant writer role
        access_controls.append(
            AccessControlOps.grant_writer_role(stream_id, GENESIS_ACCOUNT1.address)
        )
        access_controls.append(
            AccessControlOps.set_key_to_special(stream_id, special_key)
        )
        access_controls.append(
            AccessControlOps.grant_special_writer_role(
                stream_id, special_key, GENESIS_ACCOUNT1.address
            )
        )
        self.submit(MAX_U64, [], writes, access_controls)
        wait_until(
            lambda: self.kv_nodes[0].kv_get_trasanction_result(self.next_tx_seq)
            == "Commit"
        )
        first_version = self.next_tx_seq
        self.next_tx_seq += 1

        # check data and role
        self.update_data(writes)
        for stream_id_key, value in self.data.items():
            stream_id, key = stream_id_key.split(",")
            self.kv_nodes[0].check_equal(stream_id, key, value)
        assert_equal(
            self.kv_nodes[0].kv_is_admin(GENESIS_ACCOUNT.address, stream_id), True
        )
        assert_equal(
            self.kv_nodes[0].kv_is_writer_of_stream(
                GENESIS_ACCOUNT1.address, stream_id
            ),
            True,
        )
        assert_equal(
            self.kv_nodes[0].kv_is_writer_of_key(
                GENESIS_ACCOUNT1.address, stream_id, special_key
            ),
            True,
        )
        assert_equal(self.kv_nodes[0].kv_is_special_key(stream_id, special_key), True)
        assert_equal(
            self.kv_nodes[0].kv_has_write_permission(
                GENESIS_ACCOUNT1.address, stream_id, special_key
            ),
            True,
        )
        assert_equal(
            self.kv_nodes[0].kv_has_write_permission(
                GENESIS_ACCOUNT1.address, stream_id, rand_key()
            ),
            True,
        )

        # write and renounce
        writes = [rand_write(stream_id, writes[0][1]), rand_write(stream_id)]
        access_controls = []
        access_controls.append(
            AccessControlOps.revoke_writer_role(stream_id, GENESIS_ACCOUNT1.address)
        )
        access_controls.append(
            AccessControlOps.revoke_special_writer_role(
                stream_id, special_key, GENESIS_ACCOUNT1.address
            )
        )
        # no permission
        self.submit(first_version, [], writes, access_controls, tx_params=TX_PARAMS1)
        wait_until(
            lambda: is_access_control_permission_denied(
                self.kv_nodes[0].kv_get_trasanction_result(self.next_tx_seq)
            )
        )
        self.next_tx_seq += 1

        # commit
        self.submit(first_version, [], writes, access_controls)
        wait_until(
            lambda: self.kv_nodes[0].kv_get_trasanction_result(self.next_tx_seq)
            == "Commit"
        )
        second_version = self.next_tx_seq
        self.next_tx_seq += 1

        # check data and role
        self.update_data(writes)
        for stream_id_key, value in self.data.items():
            stream_id, key = stream_id_key.split(",")
            self.kv_nodes[0].check_equal(stream_id, key, value, second_version)
        assert_equal(
            self.kv_nodes[0].kv_has_write_permission(
                GENESIS_ACCOUNT1.address, stream_id, special_key
            ),
            False,
        )
        assert_equal(
            self.kv_nodes[0].kv_has_write_permission(
                GENESIS_ACCOUNT1.address, stream_id, rand_key()
            ),
            False,
        )

        # grant and revoke in one tx
        access_controls = []
        access_controls.append(
            AccessControlOps.grant_writer_role(stream_id, GENESIS_ACCOUNT1.address)
        )
        access_controls.append(
            AccessControlOps.revoke_writer_role(stream_id, GENESIS_ACCOUNT1.address)
        )
        access_controls.append(
            AccessControlOps.grant_special_writer_role(
                stream_id, special_key, GENESIS_ACCOUNT1.address
            )
        )
        access_controls.append(
            AccessControlOps.revoke_special_writer_role(
                stream_id, special_key, GENESIS_ACCOUNT1.address
            )
        )
        self.submit(MAX_U64, [], writes, access_controls)
        wait_until(
            lambda: self.kv_nodes[0].kv_get_trasanction_result(self.next_tx_seq)
            == "Commit"
        )
        self.next_tx_seq += 1
        assert_equal(
            self.kv_nodes[0].kv_is_writer_of_stream(
                GENESIS_ACCOUNT1.address, stream_id
            ),
            False,
        )
        assert_equal(
            self.kv_nodes[0].kv_is_writer_of_key(
                GENESIS_ACCOUNT1.address, stream_id, special_key
            ),
            False,
        )
        assert_equal(
            self.kv_nodes[0].kv_has_write_permission(
                GENESIS_ACCOUNT1.address, stream_id, special_key
            ),
            False,
        )
        assert_equal(
            self.kv_nodes[0].kv_has_write_permission(
                GENESIS_ACCOUNT1.address, stream_id, rand_key()
            ),
            False,
        )

        access_controls = []
        access_controls.append(
            AccessControlOps.revoke_writer_role(stream_id, GENESIS_ACCOUNT1.address)
        )
        access_controls.append(
            AccessControlOps.grant_writer_role(stream_id, GENESIS_ACCOUNT1.address)
        )
        access_controls.append(
            AccessControlOps.revoke_special_writer_role(
                stream_id, special_key, GENESIS_ACCOUNT1.address
            )
        )
        access_controls.append(
            AccessControlOps.grant_special_writer_role(
                stream_id, special_key, GENESIS_ACCOUNT1.address
            )
        )
        self.submit(MAX_U64, [], writes, access_controls)
        wait_until(
            lambda: self.kv_nodes[0].kv_get_trasanction_result(self.next_tx_seq)
            == "Commit"
        )
        self.next_tx_seq += 1
        assert_equal(
            self.kv_nodes[0].kv_is_writer_of_stream(
                GENESIS_ACCOUNT1.address, stream_id
            ),
            True,
        )
        assert_equal(
            self.kv_nodes[0].kv_is_writer_of_key(
                GENESIS_ACCOUNT1.address, stream_id, special_key
            ),
            True,
        )
        assert_equal(
            self.kv_nodes[0].kv_has_write_permission(
                GENESIS_ACCOUNT1.address, stream_id, special_key
            ),
            True,
        )
        assert_equal(
            self.kv_nodes[0].kv_has_write_permission(
                GENESIS_ACCOUNT1.address, stream_id, rand_key()
            ),
            True,
        )

    def cross_test(self, stream_id):
        assert_equal(
            self.kv_nodes[0].kv_has_write_permission(
                GENESIS_ACCOUNT.address, stream_id, rand_key()
            ),
            True,
        )
        special_key = rand_key()
        # first put
        writes = [rand_write(stream_id), rand_write(stream_id, special_key)]
        access_controls = []
        # grant writer role
        access_controls.append(
            AccessControlOps.grant_writer_role(stream_id, GENESIS_ACCOUNT1.address)
        )
        # set special key
        access_controls.append(
            AccessControlOps.set_key_to_special(stream_id, special_key)
        )
        self.submit(MAX_U64, [], writes, access_controls)
        wait_until(
            lambda: self.kv_nodes[0].kv_get_trasanction_result(self.next_tx_seq)
            == "Commit"
        )
        first_version = self.next_tx_seq
        self.next_tx_seq += 1

        # check data and role
        self.update_data(writes)
        for stream_id_key, value in self.data.items():
            stream_id, key = stream_id_key.split(",")
            self.kv_nodes[0].check_equal(stream_id, key, value)
        assert_equal(
            self.kv_nodes[0].kv_is_admin(GENESIS_ACCOUNT.address, stream_id), True
        )
        assert_equal(
            self.kv_nodes[0].kv_is_writer_of_stream(
                GENESIS_ACCOUNT1.address, stream_id
            ),
            True,
        )
        assert_equal(self.kv_nodes[0].kv_is_special_key(stream_id, special_key), True)
        assert_equal(
            self.kv_nodes[0].kv_has_write_permission(
                GENESIS_ACCOUNT.address, stream_id, special_key
            ),
            True,
        )
        assert_equal(
            self.kv_nodes[0].kv_has_write_permission(
                GENESIS_ACCOUNT1.address, stream_id, special_key
            ),
            False,
        )

        # write special key but no permission
        writes = [rand_write(stream_id, special_key)]
        self.submit(MAX_U64, [], writes, access_controls, tx_params=TX_PARAMS1)
        wait_until(
            lambda: is_write_permission_denied(
                self.kv_nodes[0].kv_get_trasanction_result(self.next_tx_seq)
            )
        )
        self.next_tx_seq += 1

        # grant special writer role
        self.submit(
            MAX_U64,
            [],
            [],
            [
                AccessControlOps.grant_special_writer_role(
                    stream_id, special_key, GENESIS_ACCOUNT1.address
                )
            ],
        )
        wait_until(
            lambda: self.kv_nodes[0].kv_get_trasanction_result(self.next_tx_seq)
            == "Commit"
        )
        self.next_tx_seq += 1
        assert_equal(
            self.kv_nodes[0].kv_has_write_permission(
                GENESIS_ACCOUNT1.address, stream_id, special_key
            ),
            True,
        )
        assert_equal(
            self.kv_nodes[0].kv_is_writer_of_key(
                GENESIS_ACCOUNT1.address, stream_id, special_key
            ),
            True,
        )
        assert_equal(
            self.kv_nodes[0].kv_is_writer_of_key(
                GENESIS_ACCOUNT1.address, stream_id, special_key, first_version
            ),
            False,
        )

        # write and renounce
        writes = [rand_write(stream_id, writes[0][1]), rand_write(stream_id)]
        access_controls = [AccessControlOps.renounce_writer_role(stream_id)]
        self.submit(first_version, [], writes, access_controls, tx_params=TX_PARAMS1)
        wait_until(
            lambda: self.kv_nodes[0].kv_get_trasanction_result(self.next_tx_seq)
            == "Commit"
        )
        second_version = self.next_tx_seq
        self.next_tx_seq += 1

        # check data and role
        for stream_id_key, value in self.data.items():
            stream_id, key = stream_id_key.split(",")
            self.kv_nodes[0].check_equal(stream_id, key, value, first_version)
        self.update_data(writes)
        for stream_id_key, value in self.data.items():
            stream_id, key = stream_id_key.split(",")
            self.kv_nodes[0].check_equal(stream_id, key, value, second_version)
        assert_equal(
            self.kv_nodes[0].kv_is_writer_of_stream(
                GENESIS_ACCOUNT1.address, stream_id
            ),
            False,
        )
        assert_equal(
            self.kv_nodes[0].kv_has_write_permission(
                GENESIS_ACCOUNT1.address, stream_id, rand_key()
            ),
            False,
        )
        assert_equal(
            self.kv_nodes[0].kv_has_write_permission(
                GENESIS_ACCOUNT1.address, stream_id, special_key
            ),
            True,
        )
        assert_equal(
            self.kv_nodes[0].kv_is_writer_of_key(
                GENESIS_ACCOUNT1.address, stream_id, special_key
            ),
            True,
        )

        # write special key and renounce
        writes = [rand_write(stream_id, special_key)]
        access_controls = [
            AccessControlOps.renounce_special_writer_role(stream_id, special_key)
        ]
        self.submit(MAX_U64, [], writes, access_controls, tx_params=TX_PARAMS1)
        wait_until(
            lambda: self.kv_nodes[0].kv_get_trasanction_result(self.next_tx_seq)
            == "Commit"
        )
        third_version = self.next_tx_seq
        self.next_tx_seq += 1
        self.update_data(writes)
        for stream_id_key, value in self.data.items():
            stream_id, key = stream_id_key.split(",")
            self.kv_nodes[0].check_equal(stream_id, key, value, third_version)
        assert_equal(
            self.kv_nodes[0].kv_has_write_permission(
                GENESIS_ACCOUNT1.address, stream_id, special_key
            ),
            False,
        )
        assert_equal(
            self.kv_nodes[0].kv_is_writer_of_key(
                GENESIS_ACCOUNT1.address, stream_id, special_key
            ),
            False,
        )

        # grant special writer role
        access_controls = []
        access_controls.append(
            AccessControlOps.grant_special_writer_role(
                stream_id, special_key, GENESIS_ACCOUNT1.address
            )
        )
        # sender no write permission
        self.submit(MAX_U64, [], [], access_controls, tx_params=TX_PARAMS1)
        wait_until(
            lambda: is_sender_no_write_permission(
                self.kv_nodes[0].kv_get_trasanction_result(self.next_tx_seq)
            )
        )
        self.next_tx_seq += 1
        # commit
        self.submit(MAX_U64, [], [], access_controls)
        wait_until(
            lambda: self.kv_nodes[0].kv_get_trasanction_result(self.next_tx_seq)
            == "Commit"
        )
        self.next_tx_seq += 1
        access_controls = []
        access_controls.append(
            AccessControlOps.grant_writer_role(stream_id, GENESIS_ACCOUNT1.address)
        )
        # access control permission denied
        self.submit(MAX_U64, [], [], access_controls, tx_params=TX_PARAMS1)
        wait_until(
            lambda: is_access_control_permission_denied(
                self.kv_nodes[0].kv_get_trasanction_result(self.next_tx_seq)
            )
        )
        self.next_tx_seq += 1
        # role check
        assert_equal(self.kv_nodes[0].kv_is_special_key(stream_id, special_key), True)
        assert_equal(
            self.kv_nodes[0].kv_has_write_permission(
                GENESIS_ACCOUNT1.address, stream_id, special_key
            ),
            True,
        )
        assert_equal(
            self.kv_nodes[0].kv_is_writer_of_key(
                GENESIS_ACCOUNT1.address, stream_id, special_key
            ),
            True,
        )
        # set key to normal
        access_controls = []
        access_controls.append(
            AccessControlOps.set_key_to_normal(stream_id, special_key)
        )
        self.submit(MAX_U64, [], [], access_controls)
        wait_until(
            lambda: self.kv_nodes[0].kv_get_trasanction_result(self.next_tx_seq)
            == "Commit"
        )
        self.next_tx_seq += 1
        # check
        assert_equal(self.kv_nodes[0].kv_is_special_key(stream_id, special_key), False)
        assert_equal(
            self.kv_nodes[0].kv_has_write_permission(
                GENESIS_ACCOUNT1.address, stream_id, special_key
            ),
            False,
        )
        assert_equal(
            self.kv_nodes[0].kv_is_writer_of_key(
                GENESIS_ACCOUNT1.address, stream_id, special_key
            ),
            True,
        )


if __name__ == "__main__":
    KVAccessControlTest().main()
