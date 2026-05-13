use anyhow::{bail, Result};
use ethereum_types::{H160, H256};
use kv_types::{AccessControlSet, KeyValuePair, StreamWriteSet};
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
                for stmt in SqliteDBStatements::CREATE_STREAM_INDEX_STATEMENTS.iter() {
                    conn.execute(stmt, [])?;
                }
                // access control table
                conn.execute(
                    SqliteDBStatements::CREATE_ACCESS_CONTROL_TABLE_STATEMENT,
                    [],
                )?;
                for stmt in SqliteDBStatements::CREATE_ACCESS_CONTROL_INDEX_STATEMENTS.iter() {
                    conn.execute(stmt, [])?;
                }
                // tx table
                conn.execute(SqliteDBStatements::CREATE_TX_TABLE_STATEMENT, [])?;
                for stmt in SqliteDBStatements::CREATE_TX_INDEX_STATEMENTS.iter() {
                    conn.execute(stmt, [])?;
                }
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
    ) -> Result<()> {
        self.connection
            .call(move |conn| {
                let tx = conn.transaction()?;
                let version = tx_seq;

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
                                ":end_index": stream_write.end_index
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
}
