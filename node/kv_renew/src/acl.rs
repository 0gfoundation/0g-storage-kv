//! Replays a stream's effective ACL snapshot (spec §5) into a fresh
//! `StreamDataBuilder`, so a renewal resubmission re-anchors the current
//! admins/writers/special-keys/special-writers rather than relying on the
//! chain to remember old grants forever.
//!
//! The signer's own admin grant is skipped: the replayer already drops an
//! account's self-grant of the role it's submitting under, and a fresh
//! resync auto-admins the uploader anyway, so emitting it here would be a
//! redundant no-op op that only wastes payload space.

use ethereum_types::{H160, H256};
use ethers::types::Address;
use kv_types::EffectiveAcl;
use zg_storage_client::kv::builder::StreamDataBuilder;

/// Emits one access-control op per effective-ACL entry into `builder`,
/// skipping `signer`'s own admin grant. Returns the number of ops emitted.
pub fn emit_acl_ops(
    builder: &mut StreamDataBuilder,
    stream_id: H256,
    acl: &EffectiveAcl,
    signer: H160,
) -> usize {
    let mut n = 0;
    let to_addr = |a: &H160| Address::from_slice(a.as_bytes());

    for admin in acl.admins.iter().filter(|a| **a != signer) {
        builder.grant_admin_role(stream_id, to_addr(admin));
        n += 1;
    }
    for w in &acl.writers {
        builder.grant_writer_role(stream_id, to_addr(w));
        n += 1;
    }
    for k in &acl.special_keys {
        builder.set_key_to_special(stream_id, k.clone());
        n += 1;
    }
    for (k, a) in &acl.special_writers {
        builder.grant_special_writer_role(stream_id, k.clone(), to_addr(a));
        n += 1;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use zg_storage_client::kv::types::AccessControlType;

    // The signer sits in *every* category (admins, writers, special_writers),
    // not just admins — a regression that also (incorrectly) filtered the
    // signer out of writers/special_writers would stay green against a
    // signer-in-admins-only fixture. Only the signer's own ADMIN grant is
    // meant to be skipped; its writer and special-writer grants must still
    // be emitted like anyone else's.
    #[test]
    fn emit_skips_only_signers_admin_grant() {
        let sid = H256::repeat_byte(4);
        let signer = H160::repeat_byte(1);
        let other = H160::repeat_byte(2);
        let acl = EffectiveAcl {
            admins: vec![signer, other],
            writers: vec![signer, other],
            special_keys: vec![b"s".to_vec()],
            special_writers: vec![(b"s".to_vec(), signer), (b"s".to_vec(), other)],
        };
        let mut b = StreamDataBuilder::new(u64::MAX);
        let n = emit_acl_ops(&mut b, sid, &acl, signer);
        // other's admin grant (1) + both writer grants (2) + special key (1)
        // + both special-writer grants (2) = 6; only signer's own admin
        // grant is skipped.
        assert_eq!(n, 6);
        let controls = b.build(None).unwrap().controls;
        assert_eq!(controls.len(), 6);

        let signer_addr = Address::from_slice(signer.as_bytes());
        let count = |control_type_matches: fn(&AccessControlType) -> bool, account: Address| {
            controls
                .iter()
                .filter(|c| control_type_matches(&c.control_type) && c.account == Some(account))
                .count()
        };

        assert_eq!(
            count(
                |t| matches!(t, AccessControlType::GrantAdminRole),
                signer_addr
            ),
            0,
            "signer's own admin grant must be skipped"
        );
        assert_eq!(
            count(
                |t| matches!(t, AccessControlType::GrantWriteRole),
                signer_addr
            ),
            1,
            "signer's writer grant must still be emitted"
        );
        assert_eq!(
            count(
                |t| matches!(t, AccessControlType::GrantSpecialWriteRole),
                signer_addr
            ),
            1,
            "signer's special-writer grant must still be emitted"
        );
    }
}
