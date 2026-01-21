from utility.utils import arrange_port, PortCategory

def kv_rpc_port(n):
    return arrange_port(PortCategory.KV_RPC, n)
