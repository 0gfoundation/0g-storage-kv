use anyhow::{bail, Result};
use ethereum_types::{H160, H256};
use kv_types::{AccessControlSet, KeyValuePair, RenewAttempt, StaleKey, StreamWriteSet};
use ssz::{Decode, Encode};
use std::{path::Path, sync::Arc};

use rusqlite::named_params;
use tokio_rusqlite::Connection;

use crate::error::Error;

use super::sqlite_db_statements::SqliteDBStatements;

pub struct StreamStore {
    connection: Connection,
}

fn convert_to_i64(x: u64) -> i64 {
    if x > i64::MAX as u64 {
        (x - i64::MAX as u64 - 1) as i64
    } else {
        x as i64 - i64::MAX - 1
    }
}

fn convert_to_u64(x: i64) -> u64 {
    if x < 0 {
        (x + i64::MAX + 1) as u64
    } else {
        x as u64 + i64::MAX as u64 + 1
    }
}

fn add_time_columns_if_missing(conn: &rusqlite::Connection, table: &str) -> rusqlite::Result<()> {
    let (mut has_created, mut has_updated) = (false, false);
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", table))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        match row.get::<_, String>(1)?.as_str() {
            "created_at" => has_created = true,
            "updated_at" => has_updated = true,
            _ => {}
        }
    }
    if !has_created {
        conn.execute(
            &format!("ALTER TABLE {} ADD COLUMN created_at INTEGER", table),
            [],
        )?;
    }
    if !has_updated {
        conn.execute(
            &format!("ALTER TABLE {} ADD COLUMN updated_at INTEGER", table),
            [],
        )?;
    }
    Ok(())
}

impl StreamStore {
    pub async fn create_tables_if_not_exist(&self) -> Result<()> {
        self.connection
            .call(|conn| {
                // misc table
                conn.execute(SqliteDBStatements::CREATE_MISC_TABLE_STATEMENT, [])?;
                {
                    let mut stmt = conn.prepare(SqliteDBStatements::SEED_MISC_ROW_STATEMENT)?;
                    stmt.execute(named_params! {
                        ":data_sync_progress": i64::MIN,
                        ":stream_replay_progress": i64::MIN,
                    })?;
                }
                // stream table
                conn.execute(SqliteDBStatements::CREATE_STREAM_TABLE_STATEMENT, [])?;
                add_time_columns_if_missing(conn, "t_stream")?;
                for stmt in SqliteDBStatements::CREATE_STREAM_INDEX_STATEMENTS.iter() {
                    conn.execute(stmt, [])?;
                }
                // access control table
                conn.execute(
                    SqliteDBStatements::CREATE_ACCESS_CONTROL_TABLE_STATEMENT,
                    [],
                )?;
                add_time_columns_if_missing(conn, "t_access_control")?;
                for stmt in SqliteDBStatements::CREATE_ACCESS_CONTROL_INDEX_STATEMENTS.iter() {
                    conn.execute(stmt, [])?;
                }
                // tx table
                conn.execute(SqliteDBStatements::CREATE_TX_TABLE_STATEMENT, [])?;
                for stmt in SqliteDBStatements::CREATE_TX_INDEX_STATEMENTS.iter() {
                    conn.execute(stmt, [])?;
                }
                // renew attempt-tracking table
                conn.execute(SqliteDBStatements::CREATE_RENEW_TABLE_STATEMENT, [])?;
                Ok(())
            })
            .await
    }

    pub async fn new_in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory().await?;
        Ok(Self { connection })
    }

    pub async fn new(path: impl AsRef<Path>) -> Result<Self> {
        let connection = Connection::open(path).await?;
        Ok(Self { connection })
    }

    pub async fn get_stream_ids(&self) -> Result<Vec<H256>> {
        self.connection
            .call(|conn| {
                let mut stmt = conn.prepare(SqliteDBStatements::GET_STREAM_IDS_STATEMENT)?;
                let mut rows = stmt.query_map([], |row| row.get(0))?;
                if let Some(raw_data) = rows.next() {
                    let raw_stream_ids: Vec<u8> = raw_data?;
                    return Ok(Vec::<H256>::from_ssz_bytes(&raw_stream_ids).map_err(Error::from)?);
                }
                Ok(vec![])
            })
            .await
    }

    pub async fn update_stream_ids(&self, stream_ids: Vec<u8>) -> Result<()> {
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare(SqliteDBStatements::UPDATE_STREAM_IDS_STATEMENT)?;
                stmt.execute(named_params! {
                    ":stream_ids": stream_ids,
                    ":id": 0,
                })?;
                Ok(())
            })
            .await
    }

    pub async fn reset_stream_sync(&self, stream_ids: Vec<u8>) -> Result<()> {
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare(SqliteDBStatements::RESET_STERAM_SYNC_STATEMENT)?;
                stmt.execute(named_params! {
                    ":data_sync_progress": convert_to_i64(0),
                    ":stream_replay_progress": convert_to_i64(0),
                    ":stream_ids": stream_ids,
                    ":id": 0,
                })?;
                Ok(())
            })
            .await
    }

    pub async fn get_stream_data_sync_progress(&self) -> Result<u64> {
        self.connection
            .call(|conn| {
                let mut stmt =
                    conn.prepare(SqliteDBStatements::GET_STREAM_DATA_SYNC_PROGRESS_STATEMENT)?;
                let mut rows = stmt.query_map([], |row| row.get(0))?;
                if let Some(raw_data) = rows.next() {
                    return Ok(convert_to_u64(raw_data?));
                }
                Ok(0)
            })
            .await
    }

    pub async fn update_stream_data_sync_progress(
        &self,
        from: u64,
        progress: u64,
    ) -> Result<usize> {
        self.connection
            .call(move |conn| {
                let mut stmt =
                    conn.prepare(SqliteDBStatements::UPDATE_STREAM_DATA_SYNC_PROGRESS_STATEMENT)?;
                Ok(stmt.execute(named_params! {
                    ":data_sync_progress": convert_to_i64(progress),
                    ":id": 0,
                    ":from": convert_to_i64(from),
                })?)
            })
            .await
    }

    pub async fn get_stream_replay_progress(&self) -> Result<u64> {
        self.connection
            .call(|conn| {
                let mut stmt =
                    conn.prepare(SqliteDBStatements::GET_STREAM_REPLAY_PROGRESS_STATEMENT)?;
                let mut rows = stmt.query_map([], |row| row.get(0))?;
                if let Some(raw_data) = rows.next() {
                    return Ok(convert_to_u64(raw_data?));
                }
                Ok(0)
            })
            .await
    }

    pub async fn update_stream_replay_progress(&self, from: u64, progress: u64) -> Result<usize> {
        self.connection
            .call(move |conn| {
                let mut stmt =
                    conn.prepare(SqliteDBStatements::UPDATE_STREAM_REPLAY_PROGRESS_STATEMENT)?;
                Ok(stmt.execute(named_params! {
                    ":stream_replay_progress": convert_to_i64(progress),
                    ":id": 0,
                    ":from": convert_to_i64(from),
                })?)
            })
            .await
    }

    pub async fn get_latest_version_before(
        &self,
        stream_id: H256,
        key: Arc<Vec<u8>>,
        before: u64,
    ) -> Result<u64> {
        self.connection
            .call(move |conn| {
                let mut stmt =
                    conn.prepare(SqliteDBStatements::GET_LATEST_VERSION_BEFORE_STATEMENT)?;
                let mut rows = stmt.query_map(
                    named_params! {
                        ":stream_id": stream_id.as_ssz_bytes(),
                        ":key": key,
                        ":before": convert_to_i64(before),
                    },
                    |row| row.get(0),
                )?;
                if let Some(raw_data) = rows.next() {
                    match raw_data {
                        Ok(x) => {
                            return Ok(convert_to_u64(x));
                        }
                        Err(_) => return Ok(0),
                    }
                }
                Ok(0)
            })
            .await
    }

    pub async fn is_new_stream(&self, stream_id: H256, version: u64) -> Result<bool> {
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare(SqliteDBStatements::IS_NEW_STREAM_STATEMENT)?;
                let mut rows = stmt.query_map(
                    named_params! {
                        ":stream_id": stream_id.as_ssz_bytes(),
                        ":version": convert_to_i64(version),
                    },
                    |_| Ok(1),
                )?;
                if rows.next().is_some() {
                    return Ok(false);
                }
                Ok(true)
            })
            .await
    }

    pub async fn is_special_key(
        &self,
        stream_id: H256,
        key: Arc<Vec<u8>>,
        version: u64,
    ) -> Result<bool> {
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare(SqliteDBStatements::IS_SPECIAL_KEY_STATEMENT)?;
                let mut rows = stmt.query_map(
                    named_params! {
                        ":stream_id": stream_id.as_ssz_bytes(),
                        ":key": key,
                        ":version": convert_to_i64(version),
                    },
                    |row| row.get(0),
                )?;
                if let Some(raw_data) = rows.next() {
                    match raw_data? {
                        AccessControlOps::SET_KEY_TO_NORMAL => Ok(false),
                        AccessControlOps::SET_KEY_TO_SPECIAL => Ok(true),
                        _ => {
                            bail!("is_special_key: unexpected access control op type");
                        }
                    }
                } else {
                    Ok(false)
                }
            })
            .await
    }

    pub async fn is_admin(&self, account: H160, stream_id: H256, version: u64) -> Result<bool> {
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare(SqliteDBStatements::IS_ADMIN_STATEMENT)?;
                let mut rows = stmt.query_map(
                    named_params! {
                        ":stream_id": stream_id.as_ssz_bytes(),
                        ":account": account.as_ssz_bytes(),
                        ":version": convert_to_i64(version),
                    },
                    |row| row.get(0),
                )?;
                if let Some(raw_data) = rows.next() {
                    match raw_data? {
                        AccessControlOps::GRANT_ADMIN_ROLE => {
                            return Ok(true);
                        }
                        AccessControlOps::RENOUNCE_ADMIN_ROLE => {
                            return Ok(false);
                        }
                        _ => {
                            bail!("is_admin: unexpected access control type");
                        }
                    }
                }
                Ok(false)
            })
            .await
    }

    pub async fn is_writer_of_key(
        &self,
        account: H160,
        stream_id: H256,
        key: Arc<Vec<u8>>,
        version: u64,
    ) -> Result<bool> {
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare(SqliteDBStatements::IS_WRITER_FOR_KEY_STATEMENT)?;
                let mut rows = stmt.query_map(
                    named_params! {
                        ":stream_id": stream_id.as_ssz_bytes(),
                        ":key": key,
                        ":account": account.as_ssz_bytes(),
                        ":version": convert_to_i64(version),
                    },
                    |row| row.get(0),
                )?;
                if let Some(raw_data) = rows.next() {
                    match raw_data? {
                        AccessControlOps::GRANT_SPECIAL_WRITER_ROLE => {
                            return Ok(true);
                        }
                        AccessControlOps::REVOKE_SPECIAL_WRITER_ROLE
                        | AccessControlOps::RENOUNCE_SPECIAL_WRITER_ROLE => return Ok(false),
                        _ => {
                            bail!("is_writer_of_key: unexpected access control op type");
                        }
                    }
                };
                Ok(false)
            })
            .await
    }

    pub async fn can_write(&self, account: H160, stream_id: H256, version: u64) -> Result<bool> {
        Ok(self.is_new_stream(stream_id, version).await?
            || self.is_admin(account, stream_id, version).await?
            || self
                .is_writer_of_stream(account, stream_id, version)
                .await?
            || self
                .special_writer_key_cnt_in_stream(account, stream_id, version)
                .await?
                > 0)
    }

    pub async fn is_writer_of_stream(
        &self,
        account: H160,
        stream_id: H256,
        version: u64,
    ) -> Result<bool> {
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare(SqliteDBStatements::IS_WRITER_FOR_STREAM_STATEMENT)?;
                let mut rows = stmt.query_map(
                    named_params! {
                        ":stream_id": stream_id.as_ssz_bytes(),
                        ":account": account.as_ssz_bytes(),
                        ":version": convert_to_i64(version),
                    },
                    |row| row.get(0),
                )?;
                if let Some(raw_data) = rows.next() {
                    match raw_data? {
                        AccessControlOps::GRANT_WRITER_ROLE => Ok(true),
                        AccessControlOps::REVOKE_WRITER_ROLE
                        | AccessControlOps::RENOUNCE_WRITER_ROLE => Ok(false),
                        _ => {
                            bail!("is_writer_of_stream: unexpected access control op type");
                        }
                    }
                } else {
                    Ok(false)
                }
            })
            .await
    }

    pub async fn special_writer_key_cnt_in_stream(
        &self,
        account: H160,
        stream_id: H256,
        version: u64,
    ) -> Result<u64> {
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare(SqliteDBStatements::IS_SPECIAL_WRITER_STATEMENT)?;
                let mut rows = stmt.query_map(
                    named_params! {
                        ":stream_id": stream_id.as_ssz_bytes(),
                        ":account": account.as_ssz_bytes(),
                        ":version": convert_to_i64(version),
                    },
                    |row| row.get(0),
                )?;
                if let Some(raw_data) = rows.next() {
                    Ok(raw_data?)
                } else {
                    Ok(0)
                }
            })
            .await
    }

    pub async fn has_write_permission(
        &self,
        account: H160,
        stream_id: H256,
        key: Arc<Vec<u8>>,
        version: u64,
    ) -> Result<bool> {
        if self.is_new_stream(stream_id, version).await? {
            return Ok(true);
        }
        if self.is_admin(account, stream_id, version).await? {
            return Ok(true);
        }
        if self.is_special_key(stream_id, key.clone(), version).await? {
            self.is_writer_of_key(account, stream_id, key.clone(), version)
                .await
        } else {
            self.is_writer_of_stream(account, stream_id, version).await
        }
    }

    pub async fn put_stream(
        &self,
        tx_seq: u64,
        result: String,
        commit_data: Option<(StreamWriteSet, AccessControlSet)>,
        block_time: Option<u64>,
    ) -> Result<()> {
        self.connection
            .call(move |conn| {
                let tx = conn.transaction()?;
                let version = tx_seq;
                let ts: Option<i64> = block_time.map(|t| t as i64);

                if tx.execute(
                    SqliteDBStatements::UPDATE_STREAM_REPLAY_PROGRESS_STATEMENT,
                    named_params! {
                        ":stream_replay_progress": convert_to_i64(version + 1),
                        ":id": 0,
                        ":from": convert_to_i64(version),
                    },
                )? == 0
                {
                    return Err(anyhow::Error::msg("tx_seq not match"));
                }

                if let Some((stream_write_set, access_control_set)) = commit_data {
                    for stream_write in stream_write_set.stream_writes.iter() {
                        tx.execute(
                            SqliteDBStatements::PUT_STREAM_WRITE_STATEMENT,
                            named_params! {
                                ":stream_id": stream_write.stream_id.as_ssz_bytes(),
                                ":key": stream_write.key,
                                ":version": convert_to_i64(version),
                                ":start_index": stream_write.start_index,
                                ":end_index": stream_write.end_index,
                                ":ts": ts,
                            },
                        )?;
                    }
                    for access_control in access_control_set.access_controls.iter() {
                        tx.execute(
                            SqliteDBStatements::PUT_ACCESS_CONTROL_STATEMENT,
                            named_params! {
                                ":stream_id": access_control.stream_id.as_ssz_bytes(),
                                ":key": access_control.key,
                                ":version": convert_to_i64(version),
                                ":account": access_control.account.as_ssz_bytes(),
                                ":op_type": access_control.op_type,
                                ":operator": access_control.operator.as_ssz_bytes(),
                                ":ts": ts,
                            },
                        )?;
                    }
                }
                tx.execute(
                    SqliteDBStatements::FINALIZE_TX_STATEMENT,
                    named_params! {
                        ":tx_seq": convert_to_i64(tx_seq),
                        ":result": result,
                    },
                )?;
                tx.commit()?;
                Ok(())
            })
            .await
    }

    pub async fn get_stream_key_value(
        &self,
        stream_id: H256,
        key: Arc<Vec<u8>>,
        version: u64,
    ) -> Result<Option<KeyValuePair>> {
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare(SqliteDBStatements::GET_STREAM_KEY_VALUE_STATEMENT)?;
                let mut rows = stmt.query_map(
                    named_params! {
                        ":stream_id": stream_id.as_ssz_bytes(),
                        ":key": key,
                        ":version": convert_to_i64(version),
                    },
                    |row| {
                        Ok(KeyValuePair {
                            stream_id,
                            key: vec![],
                            start_index: row.get(1)?,
                            end_index: row.get(2)?,
                            version: convert_to_u64(row.get(0)?),
                        })
                    },
                )?;
                if let Some(raw_data) = rows.next() {
                    return Ok(Some(raw_data?));
                }
                Ok(None)
            })
            .await
    }

    pub async fn get_next_stream_key_value(
        &self,
        stream_id: H256,
        key: Arc<Vec<u8>>,
        version: u64,
        inclusive: bool,
    ) -> Result<Option<KeyValuePair>> {
        self.connection
            .call(move |conn| {
                let mut stmt = if inclusive {
                    conn.prepare(SqliteDBStatements::GET_NEXT_KEY_VALUE_STATEMENT_INCLUSIVE)?
                } else {
                    conn.prepare(SqliteDBStatements::GET_NEXT_KEY_VALUE_STATEMENT)?
                };
                let mut rows = stmt.query_map(
                    named_params! {
                        ":stream_id": stream_id.as_ssz_bytes(),
                        ":key": key,
                        ":version": convert_to_i64(version),
                    },
                    |row| {
                        Ok(KeyValuePair {
                            stream_id,
                            key: row.get(1)?,
                            start_index: row.get(2)?,
                            end_index: row.get(3)?,
                            version: convert_to_u64(row.get(0)?),
                        })
                    },
                )?;
                if let Some(raw_data) = rows.next() {
                    return Ok(Some(raw_data?));
                }
                Ok(None)
            })
            .await
    }

    pub async fn get_prev_stream_key_value(
        &self,
        stream_id: H256,
        key: Arc<Vec<u8>>,
        version: u64,
        inclusive: bool,
    ) -> Result<Option<KeyValuePair>> {
        self.connection
            .call(move |conn| {
                let mut stmt = if inclusive {
                    conn.prepare(SqliteDBStatements::GET_PREV_KEY_VALUE_STATEMENT_INCLUSIVE)?
                } else {
                    conn.prepare(SqliteDBStatements::GET_PREV_KEY_VALUE_STATEMENT)?
                };
                let mut rows = stmt.query_map(
                    named_params! {
                        ":stream_id": stream_id.as_ssz_bytes(),
                        ":key": key,
                        ":version": convert_to_i64(version),
                    },
                    |row| {
                        Ok(KeyValuePair {
                            stream_id,
                            key: row.get(1)?,
                            start_index: row.get(2)?,
                            end_index: row.get(3)?,
                            version: convert_to_u64(row.get(0)?),
                        })
                    },
                )?;
                if let Some(raw_data) = rows.next() {
                    return Ok(Some(raw_data?));
                }
                Ok(None)
            })
            .await
    }

    pub async fn get_first(&self, stream_id: H256, version: u64) -> Result<Option<KeyValuePair>> {
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare(SqliteDBStatements::GET_FIRST_KEY_VALUE_STATEMENT)?;
                let mut rows = stmt.query_map(
                    named_params! {
                        ":stream_id": stream_id.as_ssz_bytes(),
                        ":version": convert_to_i64(version),
                    },
                    |row| {
                        Ok(KeyValuePair {
                            stream_id,
                            key: row.get(1)?,
                            start_index: row.get(2)?,
                            end_index: row.get(3)?,
                            version: convert_to_u64(row.get(0)?),
                        })
                    },
                )?;
                if let Some(raw_data) = rows.next() {
                    return Ok(Some(raw_data?));
                }
                Ok(None)
            })
            .await
    }

    pub async fn get_last(&self, stream_id: H256, version: u64) -> Result<Option<KeyValuePair>> {
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare(SqliteDBStatements::GET_LAST_KEY_VALUE_STATEMENT)?;
                let mut rows = stmt.query_map(
                    named_params! {
                        ":stream_id": stream_id.as_ssz_bytes(),
                        ":version": convert_to_i64(version),
                    },
                    |row| {
                        Ok(KeyValuePair {
                            stream_id,
                            key: row.get(1)?,
                            start_index: row.get(2)?,
                            end_index: row.get(3)?,
                            version: convert_to_u64(row.get(0)?),
                        })
                    },
                )?;
                if let Some(raw_data) = rows.next() {
                    return Ok(Some(raw_data?));
                }
                Ok(None)
            })
            .await
    }

    pub async fn get_stale_stream_keys(
        &self,
        stream_id: H256,
        cutoff: u64,
        cursor: Vec<u8>,
        limit: u64,
    ) -> Result<Vec<StaleKey>> {
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare(SqliteDBStatements::GET_STALE_STREAM_KEYS_STATEMENT)?;
                let rows = stmt.query_map(
                    named_params! {
                        ":stream_id": stream_id.as_ssz_bytes(),
                        ":cursor": cursor,
                        ":cutoff": cutoff as i64,
                        ":limit": limit as i64,
                    },
                    |row| {
                        Ok(StaleKey {
                            stream_id,
                            key: row.get(0)?,
                            version: convert_to_u64(row.get(1)?),
                            start_index: row.get(2)?,
                            end_index: row.get(3)?,
                            updated_at: row.get(4)?,
                        })
                    },
                )?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
                    .map_err(Into::into)
            })
            .await
    }

    pub async fn record_renew_attempt(
        &self,
        stream_id: H256,
        key: Vec<u8>,
        ts: u64,
        tx_hash: Option<H256>,
        error: Option<String>,
    ) -> Result<()> {
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare(SqliteDBStatements::UPSERT_RENEW_ATTEMPT_STATEMENT)?;
                stmt.execute(named_params! {
                    ":stream_id": stream_id.as_ssz_bytes(),
                    ":key": key,
                    ":ts": ts as i64,
                    ":tx_hash": tx_hash.map(|h| h.as_bytes().to_vec()),
                    ":error": error,
                })?;
                Ok(())
            })
            .await
    }

    pub async fn clear_renew_attempt(&self, stream_id: H256, key: Vec<u8>) -> Result<()> {
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare(SqliteDBStatements::CLEAR_RENEW_ATTEMPT_STATEMENT)?;
                stmt.execute(named_params! {
                    ":stream_id": stream_id.as_ssz_bytes(),
                    ":key": key,
                })?;
                Ok(())
            })
            .await
    }

    pub async fn get_renew_attempt(
        &self,
        stream_id: H256,
        key: Vec<u8>,
    ) -> Result<Option<RenewAttempt>> {
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare(SqliteDBStatements::GET_RENEW_ATTEMPT_STATEMENT)?;
                let mut rows = stmt.query_map(
                    named_params! {
                        ":stream_id": stream_id.as_ssz_bytes(),
                        ":key": key,
                    },
                    |row| {
                        let attempts: i64 = row.get(0)?;
                        let last_attempt_ts: i64 = row.get(1)?;
                        let last_tx_hash: Option<Vec<u8>> = row.get(2)?;
                        let last_error: Option<String> = row.get(3)?;
                        Ok(RenewAttempt {
                            attempts: attempts as u64,
                            last_attempt_ts: last_attempt_ts as u64,
                            last_tx_hash: last_tx_hash.map(|b| H256::from_slice(&b)),
                            last_error,
                        })
                    },
                )?;
                if let Some(raw_data) = rows.next() {
                    return Ok(Some(raw_data?));
                }
                Ok(None)
            })
            .await
    }

    pub async fn list_stuck_renewals(
        &self,
        min_attempts: u64,
        limit: u64,
    ) -> Result<Vec<(H256, Vec<u8>, RenewAttempt)>> {
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare(SqliteDBStatements::LIST_STUCK_RENEWALS_STATEMENT)?;
                let rows = stmt.query_map(
                    named_params! {
                        ":min_attempts": min_attempts as i64,
                        ":limit": limit as i64,
                    },
                    |row| {
                        let stream_id_bytes: Vec<u8> = row.get(0)?;
                        let key: Vec<u8> = row.get(1)?;
                        let attempts: i64 = row.get(2)?;
                        let last_attempt_ts: i64 = row.get(3)?;
                        let last_tx_hash: Option<Vec<u8>> = row.get(4)?;
                        let last_error: Option<String> = row.get(5)?;
                        Ok((
                            H256::from_slice(&stream_id_bytes),
                            key,
                            RenewAttempt {
                                attempts: attempts as u64,
                                last_attempt_ts: last_attempt_ts as u64,
                                last_tx_hash: last_tx_hash.map(|b| H256::from_slice(&b)),
                                last_error,
                            },
                        ))
                    },
                )?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
                    .map_err(Into::into)
            })
            .await
    }

    pub async fn get_tx_result(&self, tx_seq: u64) -> Result<Option<String>> {
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare(SqliteDBStatements::GET_TX_RESULT_STATEMENT)?;
                let mut rows = stmt
                    .query_map(named_params! {":tx_seq": convert_to_i64(tx_seq)}, |row| {
                        row.get(0)
                    })?;
                if let Some(raw_data) = rows.next() {
                    return Ok(Some(raw_data?));
                }
                Ok(None)
            })
            .await
    }

    pub async fn revert_to(&self, tx_seq: u64) -> Result<()> {
        let stream_data_sync_progress = self.get_stream_data_sync_progress().await?;
        let stream_replay_progress = self.get_stream_replay_progress().await?;

        assert!(
            stream_data_sync_progress >= stream_replay_progress,
            "stream replay progress ahead than data sync progress"
        );

        if tx_seq == u64::MAX {
            self.connection
                .call(move |conn| {
                    let tx_seq = convert_to_i64(0);
                    let tx = conn.transaction()?;
                    tx.execute(
                        SqliteDBStatements::UPDATE_STREAM_DATA_SYNC_PROGRESS_STATEMENT,
                        named_params! {
                            ":data_sync_progress": tx_seq,
                            ":id": 0,
                            ":from": convert_to_i64(stream_data_sync_progress),
                        },
                    )?;

                    tx.execute(
                        SqliteDBStatements::UPDATE_STREAM_REPLAY_PROGRESS_STATEMENT,
                        named_params! {
                            ":stream_replay_progress": tx_seq,
                            ":id": 0,
                            ":from": convert_to_i64(stream_replay_progress),
                        },
                    )?;

                    tx.execute(SqliteDBStatements::DELETE_ALL_TX_STATEMENT, [])?;
                    tx.execute(SqliteDBStatements::DELETE_ALL_STREAM_WRITE_STATEMENT, [])?;
                    tx.execute(SqliteDBStatements::DELETE_ALL_ACCESS_CONTROL_STATEMENT, [])?;

                    tx.commit()?;
                    Ok::<(), anyhow::Error>(())
                })
                .await?;
        } else if tx_seq < stream_data_sync_progress {
            if tx_seq < stream_replay_progress {
                self.connection
                    .call(move |conn| {
                        let tx_seq = convert_to_i64(tx_seq);
                        let tx = conn.transaction()?;
                        tx.execute(
                            SqliteDBStatements::UPDATE_STREAM_DATA_SYNC_PROGRESS_STATEMENT,
                            named_params! {
                                ":data_sync_progress": tx_seq + 1,
                                ":id": 0,
                                ":from": convert_to_i64(stream_data_sync_progress),
                            },
                        )?;

                        tx.execute(
                            SqliteDBStatements::UPDATE_STREAM_REPLAY_PROGRESS_STATEMENT,
                            named_params! {
                                ":stream_replay_progress": tx_seq + 1,
                                ":id": 0,
                                ":from": convert_to_i64(stream_replay_progress),
                            },
                        )?;

                        tx.execute(
                            SqliteDBStatements::DELETE_TX_STATEMENT,
                            named_params! {":tx_seq": tx_seq},
                        )?;
                        tx.execute(
                            SqliteDBStatements::DELETE_STREAM_WRITE_STATEMENT,
                            named_params! {":version": tx_seq},
                        )?;
                        tx.execute(
                            SqliteDBStatements::DELETE_ACCESS_CONTROL_STATEMENT,
                            named_params! {":version": tx_seq},
                        )?;

                        tx.commit()?;
                        Ok::<(), anyhow::Error>(())
                    })
                    .await?;
            } else {
                self.update_stream_data_sync_progress(stream_data_sync_progress, tx_seq)
                    .await?;
            }
        }

        Ok(())
    }
}

pub struct AccessControlOps;

impl AccessControlOps {
    pub const GRANT_ADMIN_ROLE: u8 = 0x00;
    pub const RENOUNCE_ADMIN_ROLE: u8 = 0x01;
    pub const SET_KEY_TO_SPECIAL: u8 = 0x10;
    pub const SET_KEY_TO_NORMAL: u8 = 0x11;
    pub const GRANT_WRITER_ROLE: u8 = 0x20;
    pub const REVOKE_WRITER_ROLE: u8 = 0x21;
    pub const RENOUNCE_WRITER_ROLE: u8 = 0x22;
    pub const GRANT_SPECIAL_WRITER_ROLE: u8 = 0x30;
    pub const REVOKE_SPECIAL_WRITER_ROLE: u8 = 0x31;
    pub const RENOUNCE_SPECIAL_WRITER_ROLE: u8 = 0x32;
}

pub fn to_access_control_op_name(x: u8) -> &'static str {
    match x {
        0x00 => "GRANT_ADMIN_ROLE",
        0x01 => "RENOUNCE_ADMIN_ROLE",
        0x10 => "SET_KEY_TO_SPECIAL",
        0x11 => "SET_KEY_TO_NORMAL",
        0x20 => "GRANT_WRITER_ROLE",
        0x21 => "REVOKE_WRITER_ROLE",
        0x22 => "RENOUNCE_WRITER_ROLE",
        0x30 => "GRANT_SPECIAL_WRITER_ROLE",
        0x31 => "REVOKE_SPECIAL_WRITER_ROLE",
        0x32 => "RENOUNCE_SPECIAL_WRITER_ROLE",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kv_types::StreamWrite;
    use ssz::Encode;

    #[tokio::test]
    async fn update_stream_ids_works_on_fresh_db() {
        let store = StreamStore::new_in_memory().await.unwrap();
        store.create_tables_if_not_exist().await.unwrap();

        // No reset_stream_sync seeding — this should work directly.
        let id = ethereum_types::H256::from([0xab; 32]);
        store
            .update_stream_ids(vec![id].as_ssz_bytes())
            .await
            .unwrap();

        let read = store.get_stream_ids().await.unwrap();
        assert_eq!(read, vec![id]);
    }

    #[tokio::test]
    async fn migration_adds_time_columns_to_old_schema() {
        let store = StreamStore::new_in_memory().await.unwrap();
        // simulate a pre-upgrade DB: old-shape tables already exist
        store.connection.call(|conn| -> rusqlite::Result<()> {
            conn.execute(
                "CREATE TABLE t_stream (stream_id BLOB NOT NULL, key BLOB NOT NULL, version INTEGER NOT NULL, start_index INTEGER NOT NULL, end_index INTEGER NOT NULL, PRIMARY KEY (stream_id, key, version)) WITHOUT ROWID", [])?;
            conn.execute(
                "CREATE TABLE t_access_control (stream_id BLOB NOT NULL, key BLOB, version INTEGER NOT NULL, account BLOB, op_type INTEGER NOT NULL, operator BLOB NOT NULL)", [])?;
            Ok(())
        }).await.unwrap();

        store.create_tables_if_not_exist().await.unwrap();
        // columns exist and are writable on both tables
        store.connection.call(|conn| -> rusqlite::Result<()> {
            conn.execute("INSERT INTO t_stream (stream_id, key, version, start_index, end_index, created_at, updated_at) VALUES (X'01', X'02', 1, 0, 0, 5, 5)", [])?;
            conn.execute("INSERT INTO t_access_control (stream_id, version, op_type, operator, created_at, updated_at) VALUES (X'01', 1, 0, X'00', 5, 5)", [])?;
            Ok(())
        }).await.unwrap();
        // idempotent: second run must not fail with duplicate column
        store.create_tables_if_not_exist().await.unwrap();
    }

    fn write_set(stream_id: H256, key: &[u8]) -> (StreamWriteSet, AccessControlSet) {
        (
            StreamWriteSet {
                stream_writes: vec![StreamWrite {
                    stream_id,
                    key: Arc::new(key.to_vec()),
                    start_index: 0,
                    end_index: 0,
                }],
            },
            AccessControlSet {
                access_controls: vec![],
                is_admin: Default::default(),
            },
        )
    }

    #[tokio::test]
    async fn timestamps_carry_created_forward() {
        let store = StreamStore::new_in_memory().await.unwrap();
        store.create_tables_if_not_exist().await.unwrap();
        let sid = H256::repeat_byte(9);

        // put_stream's replay-progress guard requires the first commit at this
        // fresh db to use tx_seq 0 (seeded progress), so the sequence below
        // starts at 0 rather than 1.
        store
            .put_stream(0, "Commit".into(), Some(write_set(sid, b"k")), Some(100))
            .await
            .unwrap();
        store
            .put_stream(1, "Commit".into(), Some(write_set(sid, b"k")), Some(200))
            .await
            .unwrap();
        store
            .put_stream(2, "Commit".into(), Some(write_set(sid, b"k")), None)
            .await
            .unwrap();

        let rows: Vec<(u64, Option<i64>, Option<i64>)> = store
            .connection
            .call(
                move |conn| -> rusqlite::Result<Vec<(u64, Option<i64>, Option<i64>)>> {
                    let mut stmt = conn.prepare(
                        "SELECT version, created_at, updated_at FROM t_stream ORDER BY version",
                    )?;
                    let rows = stmt
                        .query_map([], |r| {
                            let version: i64 = r.get(0)?;
                            Ok((convert_to_u64(version), r.get(1)?, r.get(2)?))
                        })?
                        .collect::<std::result::Result<Vec<_>, _>>()?;
                    Ok(rows)
                },
            )
            .await
            .unwrap();

        assert_eq!(rows[0], (0, Some(100), Some(100)));
        assert_eq!(rows[1], (1, Some(100), Some(200))); // created carried forward
        assert_eq!(rows[2], (2, Some(100), None)); // no block time -> NULL updated_at
    }

    // NOTE: deviates from the task brief's literal seeds (1,2,3,4,5) because
    // put_stream's replay-progress guard requires a fresh DB's first commit to
    // be at tx_seq 0; seeds are shifted down by 1 (0,1,2,3,4) with version
    // assertions adjusted accordingly. Page1 cutoff semantics are unchanged.
    #[tokio::test]
    async fn stale_scan_latest_version_pagination_and_nulls() {
        let store = StreamStore::new_in_memory().await.unwrap();
        store.create_tables_if_not_exist().await.unwrap();
        let sid = H256::repeat_byte(1);
        // key a: old v1, fresh v2 -> NOT stale; key b: old only -> stale
        // key c: NULL ts -> excluded; key d: old -> stale
        store
            .put_stream(0, "Commit".into(), Some(write_set(sid, b"a")), Some(100))
            .await
            .unwrap();
        store
            .put_stream(1, "Commit".into(), Some(write_set(sid, b"a")), Some(9_000))
            .await
            .unwrap();
        store
            .put_stream(2, "Commit".into(), Some(write_set(sid, b"b")), Some(150))
            .await
            .unwrap();
        store
            .put_stream(3, "Commit".into(), Some(write_set(sid, b"c")), None)
            .await
            .unwrap();
        store
            .put_stream(4, "Commit".into(), Some(write_set(sid, b"d")), Some(160))
            .await
            .unwrap();

        let page1 = store
            .get_stale_stream_keys(sid, 1000, vec![], 1)
            .await
            .unwrap();
        assert_eq!(page1.len(), 1);
        assert_eq!(page1[0].key, b"b".to_vec());
        assert_eq!(page1[0].version, 2);

        let page2 = store
            .get_stale_stream_keys(sid, 1000, page1[0].key.clone(), 10)
            .await
            .unwrap();
        assert_eq!(page2.len(), 1);
        assert_eq!(page2[0].key, b"d".to_vec());
    }

    #[tokio::test]
    async fn renew_tracking_upsert_clear_and_stuck() {
        let store = StreamStore::new_in_memory().await.unwrap();
        store.create_tables_if_not_exist().await.unwrap();
        let sid = H256::repeat_byte(2);

        store
            .record_renew_attempt(sid, b"k".to_vec(), 10, None, Some("no permission".into()))
            .await
            .unwrap();
        store
            .record_renew_attempt(sid, b"k".to_vec(), 20, Some(H256::repeat_byte(7)), None)
            .await
            .unwrap();

        let a = store
            .get_renew_attempt(sid, b"k".to_vec())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(a.attempts, 2);
        assert_eq!(a.last_attempt_ts, 20);
        assert_eq!(a.last_tx_hash, Some(H256::repeat_byte(7)));
        assert_eq!(a.last_error, None);

        assert_eq!(store.list_stuck_renewals(2, 10).await.unwrap().len(), 1);
        assert_eq!(store.list_stuck_renewals(3, 10).await.unwrap().len(), 0);

        store.clear_renew_attempt(sid, b"k".to_vec()).await.unwrap();
        assert!(store
            .get_renew_attempt(sid, b"k".to_vec())
            .await
            .unwrap()
            .is_none());
    }
}
