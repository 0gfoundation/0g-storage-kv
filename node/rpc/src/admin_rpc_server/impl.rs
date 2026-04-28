use std::collections::HashSet;
use std::sync::Arc;

use ethereum_types::H256;
use jsonrpsee::core::{async_trait, RpcResult};
use ssz::Encode;
use tokio::sync::RwLock;

use storage_with_stream::Store;

use super::api::AdminRpcServer;
use crate::error;

pub struct AdminRpcServerImpl {
    pub store: Arc<RwLock<dyn Store>>,
    pub live_stream_set: Arc<RwLock<HashSet<H256>>>,
}

#[async_trait]
impl AdminRpcServer for AdminRpcServerImpl {
    async fn add_stream(&self, stream_id: H256) -> RpcResult<bool> {
        // Fast path: already registered.
        if self.live_stream_set.read().await.contains(&stream_id) {
            return Ok(true);
        }

        // Compute merged set under write lock to serialize concurrent adds.
        let mut live = self.live_stream_set.write().await;
        if live.contains(&stream_id) {
            return Ok(true);
        }
        live.insert(stream_id);
        let merged: Vec<H256> = live.iter().cloned().collect();
        drop(live);

        if let Err(e) = self
            .store
            .write()
            .await
            .update_stream_ids(merged.as_ssz_bytes())
            .await
        {
            // Roll back so a retry can re-attempt persistence; otherwise the
            // fast-path check at the top would mask permanent DB-vs-memory drift.
            self.live_stream_set.write().await.remove(&stream_id);
            return Err(error::internal_error(format!("persist stream id: {:?}", e)));
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use storage_with_stream::StoreManager;

    fn h(b: u8) -> H256 {
        H256::from([b; 32])
    }

    async fn fixture() -> AdminRpcServerImpl {
        let store: Arc<RwLock<dyn Store>> =
            Arc::new(RwLock::new(StoreManager::memorydb().await.unwrap()));
        // Seed the t_misc row with an empty stream-id set. In production this
        // is performed by `merge_persisted_streams` at startup (Task 2). We
        // replicate it here because `update_stream_ids` is a plain SQL UPDATE
        // that silently no-ops if the t_misc row does not exist; without this
        // seed, the first `add_stream` call would not persist.
        store
            .write()
            .await
            .reset_stream_sync(Vec::<H256>::new().as_ssz_bytes())
            .await
            .unwrap();
        AdminRpcServerImpl {
            store,
            live_stream_set: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    #[tokio::test]
    async fn add_stream_persists_and_updates_live() {
        let svc = fixture().await;
        assert!(svc.add_stream(h(0x1)).await.unwrap());

        // live set updated
        assert!(svc.live_stream_set.read().await.contains(&h(0x1)));

        // DB persisted
        let db_ids = svc
            .store
            .read()
            .await
            .get_holding_stream_ids()
            .await
            .unwrap();
        assert_eq!(db_ids, vec![h(0x1)]);
    }

    #[tokio::test]
    async fn add_stream_is_idempotent() {
        let svc = fixture().await;
        assert!(svc.add_stream(h(0x2)).await.unwrap());
        assert!(svc.add_stream(h(0x2)).await.unwrap());

        let db_ids = svc
            .store
            .read()
            .await
            .get_holding_stream_ids()
            .await
            .unwrap();
        assert_eq!(db_ids, vec![h(0x2)]);
        assert_eq!(svc.live_stream_set.read().await.len(), 1);
    }

    #[tokio::test]
    async fn add_stream_appends_without_dropping_existing() {
        let svc = fixture().await;
        // pre-populate as if a previous run had registered h(0x1)
        svc.live_stream_set.write().await.insert(h(0x1));
        // Use reset_stream_sync (INSERT OR REPLACE) to seed the DB row.
        // update_stream_ids is plain SQL UPDATE and silently no-ops when the
        // t_misc row does not yet exist.
        svc.store
            .write()
            .await
            .reset_stream_sync(vec![h(0x1)].as_ssz_bytes())
            .await
            .unwrap();

        assert!(svc.add_stream(h(0x2)).await.unwrap());

        let db_ids: HashSet<H256> = svc
            .store
            .read()
            .await
            .get_holding_stream_ids()
            .await
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(db_ids, HashSet::from([h(0x1), h(0x2)]));
    }
}
