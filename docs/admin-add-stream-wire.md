# `admin_addStream` JSON-RPC Wire Format

After the auth changes on branch `feature/admin-add-stream`, the KV node's admin RPC requires a wallet signature on every `admin_addStream` call. This document describes the exact wire format so external callers (notably the frontend's `/api/kv/register` Next.js route in `0g-storage-scan-frontend-new`) can construct compliant requests.

## Method

`admin_addStream(streamId, wallet, signature)`

| Param | Type | Description |
|---|---|---|
| `streamId` | `0x`-prefixed 32-byte hex (`H256`) | The stream id to register |
| `wallet` | `0x`-prefixed 20-byte hex (`H160`) | The address that signed the typed data |
| `signature` | `0x`-prefixed 65-byte hex string | Output of `eth_signTypedData_v4` |

## Signed payload (EIP-712 typed data)

Domain:

```json
{
  "name": "0G Storage Scan",
  "version": "1",
  "chainId": <node's configured chain_id>
}
```

There is **no** `verifyingContract` in the domain. The frontend's domain helper at `0g-storage-scan-frontend-new/src/lib/eip712.ts` produces the same 3-field domain.

Type:

```
RegisterStream(string purpose,address wallet,bytes32 streamId)
```

Message:

```json
{
  "purpose": "register-stream",
  "wallet": "<wallet address>",
  "streamId": "<32-byte hex>"
}
```

## Verification on the KV node

1. Reconstruct the EIP-712 digest from `streamId`, `wallet`, and the node's configured `chain_id`.
2. Call `Signature::recover(digest)` on the supplied signature.
3. Reject if the recovered address does not equal the supplied `wallet`.

If `chain_id` differs between signer and verifier, recovery yields a different address and the request is rejected. The frontend MUST sign with the chain id that matches the deployed KV node's `chain_id` config field.

## Failure responses

- Malformed signature hex → `-32602` (invalid params).
- Signature recovery error → `-32602` (invalid params).
- Recovered signer ≠ claimed wallet → `-32602` (invalid params).
- DB persistence failure → `-32603` (internal error).

## Idempotency

A second call with the same `streamId` and a valid signature returns `Ok(true)` without re-persisting. The signature does not need to be the same as the first call's; any valid signature for that `(wallet, streamId)` pair suffices.

## Frontend route update needed

The Next.js route at `0g-storage-scan-frontend-new/src/app/api/kv/register/route.ts:78` currently sends:

```json
{ "method": "admin_addStream", "params": [streamId] }
```

Update to send:

```json
{ "method": "admin_addStream", "params": [streamId, walletAddr, signature] }
```

The route already has `walletAddr` and `signature` in scope from the request body (verified by `recoverTypedDataAddress` just above), so this is a 1-line change to the params array.

## Operator: required configuration

The KV node's TOML config must set `chain_id` to match what the frontend signs against:

```toml
chain_id = 16601    # 0G testnet; adjust per deployment
```

If unset (default `0`), all admin registrations will be rejected at signature recovery — fail-safe.
