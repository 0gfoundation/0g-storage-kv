from enum import Enum, unique

from utility.utils import is_windows_platform, wait_until
from utility.build_binary import __build_from_github

ZGS_BINARY = "zgs_node.exe" if is_windows_platform() else "zgs_node"

@unique
class BuildBinaryResult(Enum):
    AlreadyExists = 0
    Installed = 1
    NotInstalled = 2

def build_zgs(dir: str) -> BuildBinaryResult:
    return __build_from_github(
        dir=dir,
        binary_name=ZGS_BINARY,
        github_url="https://github.com/0gfoundation/0g-storage-node.git",
        build_cmd="cargo build --release",
        compiled_relative_path=["target", "release"],
    )
