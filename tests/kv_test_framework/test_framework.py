import argparse
from enum import Enum
import logging
import os
import pdb
import random
import shutil
import sys
import tempfile
import time
import traceback
from pathlib import Path

from test_framework.blockchain_node import BlockChainNodeType
from test_framework.test_framework import TestFramework
from utility.utils import PortMin, is_windows_platform, wait_until, assert_equal
from kv_test_framework.kv_node import KVNode

__file_path__ = os.path.dirname(os.path.realpath(__file__))


class TestStatus(Enum):
    PASSED = 1
    FAILED = 2


TEST_EXIT_PASSED = 0
TEST_EXIT_FAILED = 1


class KVTestFramework(TestFramework):
    def __init__(self, blockchain_node_type=BlockChainNodeType.ZG):
        super().__init__(blockchain_node_type)

        self.kv_nodes = []
        binary_ext = ".exe" if is_windows_platform() else ""
        tests_dir = os.path.dirname(__file_path__)
        root_dir = os.path.dirname(tests_dir)
        self.__default_zgs_node_binary__ = os.path.join(
            tests_dir, "tmp", "zgs_node" + binary_ext
        )
        self.__default_zgs_cli_binary__ = os.path.join(
            tests_dir, "tmp", "0g-storage-client"  + binary_ext
        )
        self.__default_zgs_kv_binary__ = os.path.join(
            __file_path__, root_dir, "target", "release", "zgs_kv" + binary_ext
        )


    def add_arguments(self, parser: argparse.ArgumentParser):
        super().add_arguments(parser)

        parser.add_argument(
            "--zgs-kv",
            dest="zgs_kv",
            default=self.__default_zgs_kv_binary__,
            type=str,
        )

    def setup_kv_node(self, index, stream_ids, updated_config={}):
        assert os.path.exists(self.kv_binary), "%s should be exist" % self.kv_binary
        node = KVNode(
            index,
            self.root_dir,
            self.kv_binary,
            updated_config,
            self.contract.address(),
            self.log,
            stream_ids=stream_ids,
        )
        self.kv_nodes.append(node)
        node.setup_config()
        node.start()

        time.sleep(1)
        node.wait_for_rpc_connection()

    def stop_kv_node(self, index):
        self.kv_nodes[index].stop()

    def start_kv_node(self, index):
        self.kv_nodes[index].start()

        self.nodes[index].start()

    
    def stop_nodes(self):
        super().stop_nodes()

        for node in self.kv_nodes:
            node.stop()
    
    def __start_logging(self):
        # Add logger and logging handlers
        self.log = logging.getLogger("TestFramework")
        self.log.setLevel(logging.DEBUG)

        # Create file handler to log all messages
        fh = logging.FileHandler(
            self.options.tmpdir + "/test_framework.log", encoding="utf-8"
        )
        fh.setLevel(logging.DEBUG)

        # Create console handler to log messages to stderr. By default this logs only error messages, but can be configured with --loglevel.
        ch = logging.StreamHandler(sys.stdout)
        # User can provide log level as a number or string (eg DEBUG). loglevel was caught as a string, so try to convert it to an int
        ll = (
            int(self.options.loglevel)
            if self.options.loglevel.isdigit()
            else self.options.loglevel.upper()
        )
        ch.setLevel(ll)

        # Format logs the same as bitcoind's debug.log with microprecision (so log files can be concatenated and sorted)
        formatter = logging.Formatter(
            fmt="%(asctime)s.%(msecs)03d000Z %(name)s (%(levelname)s): %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        formatter.converter = time.gmtime
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)

        # add the handlers to the logger
        self.log.addHandler(fh)
        self.log.addHandler(ch)

    def main(self):
        parser = argparse.ArgumentParser(usage="%(prog)s [options]")
        self.add_arguments(parser)
        self.options = parser.parse_args()
        PortMin.n = self.options.port_min

        # Set up temp directory and start logging
        if self.options.tmpdir:
            self.options.tmpdir = os.path.abspath(self.options.tmpdir)
            os.makedirs(self.options.tmpdir, exist_ok=True)
        else:
            self.options.tmpdir = os.getenv(
                "KV_TESTS_LOG_DIR", default=tempfile.mkdtemp(prefix="kv_test_")
            )

        self.root_dir = self.options.tmpdir

        self.__start_logging()
        self.log.info("Root dir: %s", self.root_dir)

        if self.options.devdir:
            dst = self.options.devdir

            if os.path.islink(dst):
                os.remove(dst)
            elif os.path.isdir(dst): 
                shutil.rmtree(dst)
            elif os.path.exists(dst):
                os.remove(dst)

            os.symlink(self.options.tmpdir, dst)
            self.log.info("Symlink: %s", Path(dst).absolute())

        if self.blockchain_node_type == BlockChainNodeType.ZG:
            self.blockchain_binary = os.path.abspath(self.options.zg)
        else:
            raise NotImplementedError

        self.zgs_binary = os.path.abspath(self.options.zerog_storage)
        self.cli_binary = os.path.abspath(self.options.cli)
        self.contract_path = os.path.abspath(self.options.contract)
        self.kv_binary = os.path.abspath(self.options.zgs_kv)

        assert os.path.exists(self.contract_path), (
            "%s should be exist" % self.contract_path
        )

        if self.options.random_seed is not None:
            random.seed(self.options.random_seed)

        success = TestStatus.FAILED
        try:
            self.setup_params()
            self.setup_nodes()
            self.log.debug("========== start to run tests ==========")
            self.run_test()
            success = TestStatus.PASSED
        except AssertionError as e:
            self.log.exception("Assertion failed %s", repr(e))
        except KeyboardInterrupt as e:
            self.log.warning("Exiting after keyboard interrupt %s", repr(e))
        except Exception as e:
            self.log.error("Test exception %s %s", repr(e), traceback.format_exc())
            self.log.error(f"Test data are not deleted: {self.root_dir}")

        if success == TestStatus.FAILED and self.options.pdbonfailure:
            print("Testcase failed. Attaching python debugger. Enter ? for help")
            pdb.set_trace()

        if success == TestStatus.PASSED:
            self.log.info("Tests successful")
            exit_code = TEST_EXIT_PASSED
        else:
            self.log.error(
                "Test failed. Test logging available at %s/test_framework.log",
                self.options.tmpdir,
            )
            exit_code = TEST_EXIT_FAILED

        self.stop_nodes()

        handlers = self.log.handlers[:]
        for handler in handlers:
            self.log.removeHandler(handler)
            handler.close()
        logging.shutdown()

        if success == TestStatus.PASSED:
            shutil.rmtree(self.root_dir)

        sys.exit(exit_code)
