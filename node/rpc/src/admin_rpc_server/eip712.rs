// Helpers are introduced in this task (Task 1) but only consumed in a later
// task that wires them into the admin_addStream call site. Suppress dead-code
// warnings for the gap; they'll be exercised once the call site lands.
#![allow(dead_code)]

use ethers::abi::{encode, Token};
use ethers::types::{Address, Signature, H256, U256};
use ethers::utils::keccak256;

/// EIP-712 domain name. Must match the frontend's `EIP712_DOMAIN_NAME` in
/// `src/lib/eip712.ts`. Drift causes signature recovery to return the wrong
/// address.
pub const DOMAIN_NAME: &str = "0G Storage Scan";
pub const DOMAIN_VERSION: &str = "1";

/// The `purpose` field value the frontend sends in every `RegisterStream`
/// payload. Drift causes the struct hash to differ from what the frontend
/// signed.
pub const REGISTER_STREAM_PURPOSE: &str = "register-stream";

/// Compute the EIP-712 domain separator. The 3-field domain matches the
/// frontend's `Eip712Domain = { name, version, chainId }` — there is no
/// `verifyingContract`, so the domain typehash uses only those three fields.
pub fn domain_separator(chain_id: u64) -> [u8; 32] {
    let domain_typehash =
        keccak256(b"EIP712Domain(string name,string version,uint256 chainId)");

    let encoded = encode(&[
        Token::FixedBytes(domain_typehash.to_vec()),
        Token::FixedBytes(keccak256(DOMAIN_NAME.as_bytes()).to_vec()),
        Token::FixedBytes(keccak256(DOMAIN_VERSION.as_bytes()).to_vec()),
        Token::Uint(U256::from(chain_id)),
    ]);

    keccak256(encoded)
}

/// Compute the EIP-712 struct hash for `RegisterStream(string purpose, address wallet, bytes32 streamId)`.
/// `purpose` is hashed (per EIP-712 string encoding); `wallet` and `streamId`
/// are encoded as `address` and `bytes32` respectively.
pub fn register_stream_struct_hash(wallet: Address, stream_id: [u8; 32]) -> [u8; 32] {
    let typehash =
        keccak256(b"RegisterStream(string purpose,address wallet,bytes32 streamId)");

    let encoded = encode(&[
        Token::FixedBytes(typehash.to_vec()),
        Token::FixedBytes(keccak256(REGISTER_STREAM_PURPOSE.as_bytes()).to_vec()),
        Token::Address(wallet),
        Token::FixedBytes(stream_id.to_vec()),
    ]);

    keccak256(encoded)
}

/// Compute the full EIP-712 digest: `keccak256("\x19\x01" || domainSeparator || structHash)`.
pub fn register_stream_digest(
    wallet: Address,
    stream_id: [u8; 32],
    chain_id: u64,
) -> [u8; 32] {
    let domain = domain_separator(chain_id);
    let struct_h = register_stream_struct_hash(wallet, stream_id);

    let mut payload = Vec::with_capacity(2 + 32 + 32);
    payload.extend_from_slice(b"\x19\x01");
    payload.extend_from_slice(&domain);
    payload.extend_from_slice(&struct_h);

    keccak256(payload)
}

/// Recover the signer of a `RegisterStream` typed-data payload. Returns
/// `Ok(signer)` on a valid signature, `Err` if the signature is malformed.
/// The caller is responsible for asserting the recovered address equals the
/// expected `wallet`.
pub fn recover_register_stream_signer(
    wallet: Address,
    stream_id: [u8; 32],
    chain_id: u64,
    signature: &Signature,
) -> Result<Address, ethers::types::SignatureError> {
    let digest = register_stream_digest(wallet, stream_id, chain_id);
    signature.recover(H256::from(digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::signers::{LocalWallet, Signer};

    fn test_wallet() -> LocalWallet {
        // Hardhat default account #0; a well-known throwaway key.
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse::<LocalWallet>()
            .unwrap()
    }

    fn test_stream_id() -> [u8; 32] {
        [0xab; 32]
    }

    #[test]
    fn domain_separator_is_deterministic() {
        let s1 = domain_separator(16601);
        let s2 = domain_separator(16601);
        assert_eq!(s1, s2);
    }

    #[test]
    fn domain_separator_changes_with_chain_id() {
        let s1 = domain_separator(16601);
        let s2 = domain_separator(1);
        assert_ne!(s1, s2);
    }

    #[test]
    fn struct_hash_changes_with_wallet() {
        let h1 = register_stream_struct_hash(Address::from([0x11; 20]), test_stream_id());
        let h2 = register_stream_struct_hash(Address::from([0x22; 20]), test_stream_id());
        assert_ne!(h1, h2);
    }

    #[test]
    fn struct_hash_changes_with_stream_id() {
        let wallet = Address::from([0x11; 20]);
        let h1 = register_stream_struct_hash(wallet, [0x01; 32]);
        let h2 = register_stream_struct_hash(wallet, [0x02; 32]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn digest_changes_with_chain_id() {
        let wallet = Address::from([0x11; 20]);
        let d1 = register_stream_digest(wallet, test_stream_id(), 16601);
        let d2 = register_stream_digest(wallet, test_stream_id(), 1);
        assert_ne!(d1, d2);
    }

    #[tokio::test]
    async fn sign_and_recover_round_trip() {
        let wallet = test_wallet();
        let stream_id = test_stream_id();
        let chain_id = 16601u64;

        let digest = register_stream_digest(wallet.address(), stream_id, chain_id);
        let signature = wallet.sign_hash(H256::from(digest)).unwrap();

        let recovered =
            recover_register_stream_signer(wallet.address(), stream_id, chain_id, &signature)
                .unwrap();
        assert_eq!(recovered, wallet.address());
    }

    #[tokio::test]
    async fn wrong_chain_id_does_not_recover_to_signer() {
        let wallet = test_wallet();
        let stream_id = test_stream_id();

        // Sign with chain id 16601; verify against chain id 1.
        let digest = register_stream_digest(wallet.address(), stream_id, 16601);
        let signature = wallet.sign_hash(H256::from(digest)).unwrap();

        let recovered =
            recover_register_stream_signer(wallet.address(), stream_id, 1, &signature)
                .unwrap();
        assert_ne!(recovered, wallet.address());
    }

    #[tokio::test]
    async fn signature_from_different_key_does_not_recover_to_expected_wallet() {
        let signer = test_wallet();
        let other_wallet: LocalWallet =
            "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
                .parse()
                .unwrap();

        let stream_id = test_stream_id();
        let chain_id = 16601u64;

        // Signer signs, but we claim the wallet is other_wallet.
        let digest = register_stream_digest(other_wallet.address(), stream_id, chain_id);
        let signature = signer.sign_hash(H256::from(digest)).unwrap();

        let recovered = recover_register_stream_signer(
            other_wallet.address(),
            stream_id,
            chain_id,
            &signature,
        )
        .unwrap();
        // Should recover to signer (not other_wallet), so the equality check
        // at the call site (recovered == claimed wallet) will fail.
        assert_eq!(recovered, signer.address());
        assert_ne!(recovered, other_wallet.address());
    }

    #[tokio::test]
    async fn changing_stream_id_breaks_existing_signature() {
        let wallet = test_wallet();
        let chain_id = 16601u64;

        let digest_a = register_stream_digest(wallet.address(), [0xaa; 32], chain_id);
        let signature = wallet.sign_hash(H256::from(digest_a)).unwrap();

        // Verify the signature against a different stream_id — recovers wrong address.
        let recovered =
            recover_register_stream_signer(wallet.address(), [0xbb; 32], chain_id, &signature)
                .unwrap();
        assert_ne!(recovered, wallet.address());
    }
}
