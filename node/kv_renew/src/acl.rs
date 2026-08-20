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

    #[test]
    fn emit_skips_signer_self_grant() {
        let sid = H256::repeat_byte(4);
        let signer = H160::repeat_byte(1);
        let other = H160::repeat_byte(2);
        let acl = EffectiveAcl {
            admins: vec![signer, other],
            writers: vec![other],
            special_keys: vec![b"s".to_vec()],
            special_writers: vec![(b"s".to_vec(), other)],
        };
        let mut b = StreamDataBuilder::new(u64::MAX);
        let n = emit_acl_ops(&mut b, sid, &acl, signer);
        assert_eq!(n, 4); // other-admin grant, writer grant, special key, special writer — NOT signer's own admin
        assert_eq!(b.build(None).unwrap().controls.len(), 4);
    }
}
