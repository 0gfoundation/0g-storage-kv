use super::stream_store::AccessControlOps;
use const_format::formatcp;

pub struct SqliteDBStatements;

impl SqliteDBStatements {
    pub const RESET_STERAM_SYNC_STATEMENT: &'static str = "
        INSERT OR REPLACE INTO 
            t_misc (data_sync_progress, stream_replay_progress, stream_ids, id) 
        VALUES 
            (:data_sync_progress, :stream_replay_progress, :stream_ids, :id)
    ";

    pub const SEED_MISC_ROW_STATEMENT: &'static str = "
        INSERT OR IGNORE INTO t_misc (id, data_sync_progress, stream_replay_progress, stream_ids)
        VALUES (0, :data_sync_progress, :stream_replay_progress, X'')
    ";

    pub const FINALIZE_TX_STATEMENT: &'static str = "
        INSERT OR REPLACE INTO 
            t_tx (tx_seq, result)
        VALUES
            (:tx_seq, :result)
    ";

    pub const DELETE_TX_STATEMENT: &'static str = "DELETE FROM t_tx WHERE tx_seq > :tx_seq";

    pub const DELETE_ALL_TX_STATEMENT: &'static str = "DELETE FROM t_tx";

    pub const GET_TX_RESULT_STATEMENT: &'static str =
        "SELECT result FROM t_tx WHERE tx_seq = :tx_seq";

    pub const GET_STREAM_DATA_SYNC_PROGRESS_STATEMENT: &'static str =
        "SELECT data_sync_progress FROM t_misc WHERE id = 0";

    pub const UPDATE_STREAM_DATA_SYNC_PROGRESS_STATEMENT: &'static str =
        "UPDATE t_misc SET data_sync_progress = :data_sync_progress WHERE id = :id AND data_sync_progress = :from";

    pub const GET_STREAM_REPLAY_PROGRESS_STATEMENT: &'static str =
        "SELECT stream_replay_progress FROM t_misc WHERE id = 0";

    pub const UPDATE_STREAM_REPLAY_PROGRESS_STATEMENT: &'static str = "UPDATE t_misc SET stream_replay_progress = :stream_replay_progress WHERE id = :id AND stream_replay_progress = :from";

    pub const GET_STREAM_IDS_STATEMENT: &'static str = "SELECT stream_ids FROM t_misc WHERE id = 0";

    pub const UPDATE_STREAM_IDS_STATEMENT: &'static str =
        "UPDATE t_misc SET stream_ids = :stream_ids WHERE id = :id";

    pub const GET_LATEST_VERSION_BEFORE_STATEMENT: &'static str =
        "SELECT MAX(version) FROM t_stream WHERE stream_id = :stream_id AND key = :key AND version <= :before";

    pub const IS_NEW_STREAM_STATEMENT: &'static str =
        "SELECT 1 FROM t_access_control WHERE stream_id = :stream_id AND version <= :version LIMIT 1";

    pub const IS_SPECIAL_KEY_STATEMENT: &'static str = formatcp!(
        "
        SELECT op_type FROM
            t_access_control 
        WHERE 
            stream_id = :stream_id AND key = :key AND 
            version <= :version AND op_type in ({}, {})
        ORDER BY version DESC LIMIT 1",
        AccessControlOps::SET_KEY_TO_SPECIAL,
        AccessControlOps::SET_KEY_TO_NORMAL,
    );

    pub const IS_ADMIN_STATEMENT: &'static str = formatcp!(
        "
        SELECT op_type FROM 
            t_access_control
        WHERE
            stream_id = :stream_id AND account = :account AND
            version <= :version AND op_type in ({}, {})
        ORDER BY version DESC LIMIT 1",
        AccessControlOps::GRANT_ADMIN_ROLE,
        AccessControlOps::RENOUNCE_ADMIN_ROLE
    );

    pub const IS_SPECIAL_WRITER_STATEMENT: &'static str = formatcp!(
        "
        SELECT COUNT(*) FROM (
            SELECT * FROM 
                t_access_control
            WHERE stream_id = :stream_id AND account = :account AND
            (key, version) IN (
                    SELECT key, MAX(version) FROM
                        t_access_control
                    WHERE stream_id = :stream_id AND account = :account AND version <= :version
                    GROUP BY key
            )
        ) AS filtered
        WHERE op_type = {}
        ",
        AccessControlOps::GRANT_SPECIAL_WRITER_ROLE
    );

    pub const IS_WRITER_FOR_KEY_STATEMENT: &'static str = formatcp!(
        "
        SELECT op_type FROM 
            t_access_control
        WHERE
            stream_id = :stream_id AND key = :key AND
            account = :account AND version <= :version AND
            op_type in ({}, {}, {})
        ORDER BY version DESC LIMIT 1
    ",
        AccessControlOps::GRANT_SPECIAL_WRITER_ROLE,
        AccessControlOps::REVOKE_SPECIAL_WRITER_ROLE,
        AccessControlOps::RENOUNCE_SPECIAL_WRITER_ROLE
    );

    pub const IS_WRITER_FOR_STREAM_STATEMENT: &'static str = formatcp!(
        "
        SELECT op_type FROM 
            t_access_control
        WHERE
            stream_id = :stream_id AND account = :account AND 
            version <= :version AND op_type in ({}, {}, {})
        ORDER BY version DESC LIMIT 1
    ",
        AccessControlOps::GRANT_WRITER_ROLE,
        AccessControlOps::REVOKE_WRITER_ROLE,
        AccessControlOps::RENOUNCE_WRITER_ROLE
    );

    pub const PUT_STREAM_WRITE_STATEMENT: &'static str = "
        INSERT OR REPLACE INTO
            t_stream (stream_id, key, version, start_index, end_index)
        VALUES
            (:stream_id, :key, :version, :start_index, :end_index)
    ";

    pub const DELETE_STREAM_WRITE_STATEMENT: &'static str =
        "DELETE FROM t_stream WHERE version > :version";

    pub const DELETE_ALL_STREAM_WRITE_STATEMENT: &'static str = "DELETE FROM t_stream";

    pub const PUT_ACCESS_CONTROL_STATEMENT: &'static str = "
        INSERT OR REPLACE INTO
            t_access_control (stream_id, key, version, account, op_type, operator)
        VALUES
            (:stream_id, :key, :version, :account, :op_type, :operator)
    ";

    pub const DELETE_ACCESS_CONTROL_STATEMENT: &'static str =
        "DELETE FROM t_access_control WHERE version > :version ";

    pub const DELETE_ALL_ACCESS_CONTROL_STATEMENT: &'static str = "DELETE FROM t_access_control";

    pub const GET_STREAM_KEY_VALUE_STATEMENT: &'static str = "
        SELECT version, start_index, end_index FROM 
            t_stream
        WHERE 
            stream_id = :stream_id AND key = :key AND
            version <= :version
        ORDER BY version DESC LIMIT 1
    ";

    pub const GET_NEXT_KEY_VALUE_STATEMENT_INCLUSIVE: &'static str = "
        SELECT version, key, start_index, end_index FROM 
            t_stream
        WHERE
            stream_id = :stream_id AND key >= :key AND version <= :version
        ORDER BY key ASC, version DESC LIMIT 1
    ";

    pub const GET_NEXT_KEY_VALUE_STATEMENT: &'static str = "
        SELECT version, key, start_index, end_index FROM 
            t_stream
        WHERE
            stream_id = :stream_id AND key > :key AND version <= :version
        ORDER BY key ASC, version DESC LIMIT 1
    ";

    pub const GET_PREV_KEY_VALUE_STATEMENT_INCLUSIVE: &'static str = "
        SELECT version, key, start_index, end_index FROM 
            t_stream
        WHERE
            stream_id = :stream_id AND key <= :key AND version <= :version
        ORDER BY key DESC, version DESC LIMIT 1
    ";

    pub const GET_PREV_KEY_VALUE_STATEMENT: &'static str = "
        SELECT version, key, start_index, end_index FROM 
            t_stream
        WHERE
            stream_id = :stream_id AND key < :key AND version <= :version
        ORDER BY key DESC, version DESC LIMIT 1
    ";

    pub const GET_FIRST_KEY_VALUE_STATEMENT: &'static str = "
        SELECT version, key, start_index, end_index FROM 
            t_stream
        WHERE
            stream_id = :stream_id AND version <= :version
        ORDER BY key ASC, version DESC LIMIT 1
    ";

    pub const GET_LAST_KEY_VALUE_STATEMENT: &'static str = "
        SELECT version, key, start_index, end_index FROM 
            t_stream
        WHERE
            stream_id = :stream_id AND version <= :version
        ORDER BY key DESC, version DESC LIMIT 1
    ";

    pub const CREATE_MISC_TABLE_STATEMENT: &'static str = "
        CREATE TABLE IF NOT EXISTS t_misc (
            id INTEGER NOT NULL PRIMARY KEY,
            data_sync_progress INTEGER NOT NULL, 
            stream_replay_progress INTEGER NOT NULL, 
            stream_ids BLOB NOT NULL
        ) WITHOUT ROWID
    ";

    pub const CREATE_STREAM_TABLE_STATEMENT: &'static str = "
        CREATE TABLE IF NOT EXISTS t_stream (
            stream_id BLOB NOT NULL,
            key BLOB NOT NULL,
            version INTEGER NOT NULL,
            start_index INTEGER NOT NULL,
            end_index INTEGER NOT NULL,
            PRIMARY KEY (stream_id, key, version)
        ) WITHOUT ROWID
    ";

    pub const CREATE_STREAM_INDEX_STATEMENTS: [&'static str; 2] = [
        "CREATE INDEX IF NOT EXISTS stream_key_idx ON t_stream(stream_id, key)",
        "CREATE INDEX IF NOT EXISTS stream_version_idx ON t_stream(version)",
    ];

    pub const CREATE_ACCESS_CONTROL_TABLE_STATEMENT: &'static str = "
        CREATE TABLE IF NOT EXISTS t_access_control (
            stream_id BLOB NOT NULL,
            key BLOB,
            version INTEGER NOT NULL,
            account BLOB,
            op_type INTEGER NOT NULL,
            operator BLOB NOT NULL
        )
    ";

    pub const CREATE_ACCESS_CONTROL_INDEX_STATEMENTS: [&'static str; 5] = [
        "CREATE INDEX IF NOT EXISTS ac_version_index ON t_access_control(version)",
        "CREATE INDEX IF NOT EXISTS ac_op_type_index ON t_access_control(op_type)",
        "CREATE INDEX IF NOT EXISTS ac_account_index ON t_access_control(stream_id, account)",
        "CREATE INDEX IF NOT EXISTS ac_key_index ON t_access_control(stream_id, key)",
        "CREATE INDEX IF NOT EXISTS ac_account_key_index ON t_access_control(stream_id, key, account)",
    ];

    pub const CREATE_TX_TABLE_STATEMENT: &'static str = "
        CREATE TABLE IF NOT EXISTS t_tx (
            tx_seq INTEGER NOT NULL PRIMARY KEY,
            result TEXT
        ) WITHOUT ROWID
    ";

    pub const CREATE_TX_INDEX_STATEMENTS: [&'static str; 1] =
        ["CREATE INDEX IF NOT EXISTS tx_result_idex ON t_tx(result)"];
}
