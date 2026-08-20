from eth_utils import decode_hex
from math import log2
from utility.submission import split_nodes, create_node, MerkleTree, Leaf
from utility.merkle_tree import add_0x_prefix
from utility.spec import ENTRY_SIZE

def create_submission(data, tags, submitter):
    """Build a Flow `Submission` tuple: ((length, tags, nodes), submitter).

    `submitter` is the address the Flow contract credits as the writer -- it is
    what lands in the `Submit` event's indexed `sender` topic, and therefore
    what the KV stream ACL checks write permission against. Pass the same
    address the submit transaction is sent from.
    """
    submission_data = []
    submission_data.append(len(data))
    submission_data.append(tags)
    submission_data.append([])

    offset = 0
    nodes = []
    for chunks in split_nodes(len(data)):
        node_hash = create_node(data, offset, chunks)
        nodes.append(node_hash)

        height = int(log2(chunks))
        submission_data[2].append([decode_hex(node_hash.decode("utf-8")), height])
        offset += chunks * ENTRY_SIZE

    root_hash = nodes[-1]
    for i in range(len(nodes) - 2, -1, -1):
        tree = MerkleTree()
        tree.add_leaf(Leaf(nodes[i]))
        tree.add_leaf(Leaf(root_hash))
        root_hash = tree.get_root_hash()

    submission = [submission_data, submitter]
    return submission, add_0x_prefix(root_hash.decode("utf-8"))