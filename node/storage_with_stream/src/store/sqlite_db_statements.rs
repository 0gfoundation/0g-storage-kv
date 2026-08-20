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

    /// Groupwise-latest ACL snapshot statements (spec §5): each returns, per
    /// group key, only the row whose `version` is the max among the group's
    /// grant/revoke op_types — the caller keeps only the grant-variant rows.
    ///
    /// **Tie-handling invariant (fail-open if ever violated):** these queries
    /// assume at most one row per (stream_id, group-key, op_type-category,
    /// version) — i.e. within a single tx/version there is never more than
    /// one row for the same account (admins/writers) or key
    /// (special keys)/(key, account) (special writers) among a category's
    /// grant/revoke/renounce op_types. If two rows ever tied on `version`
    /// within a group, `version = (SELECT MAX(version) ...)` would let SQLite
    /// return *both* rows non-deterministically instead of picking one
    /// winner, and the Rust-side "keep only the grant-variant row" filter
    /// would then either double-count a grant or (if the tied pair is one
    /// grant + one revoke) leave the caller unable to tell which won —
    /// silently breaking this security-sensitive query rather than erroring.
    /// This holds today because the replayer dedups access-control ops per
    /// tx by `(op_type & 0xf0, stream_id, key, account)` before writing, and
    /// each category's non-grouped column is constant per row (e.g. the
    /// admins/writers queries group by `account` and never vary `key`, so a
    /// dedup key collision within a category can only occur for the exact
    /// same group). A future replayer change that allows multiple
    /// same-version rows per group (e.g. a batched multi-key op or relaxed
    /// dedup) must revisit this — silently, not just here.

    pub const GET_EFFECTIVE_ADMINS_STATEMENT: &'static str = formatcp!(
        "
        SELECT account, op_type FROM t_access_control a
        WHERE stream_id = :stream_id AND op_type IN ({}, {}) AND version = (
            SELECT MAX(version) FROM t_access_control b
            WHERE b.stream_id = a.stream_id AND b.account = a.account AND b.op_type IN ({}, {}))
        ORDER BY account",
        AccessControlOps::GRANT_ADMIN_ROLE,
        AccessControlOps::RENOUNCE_ADMIN_ROLE,
        AccessControlOps::GRANT_ADMIN_ROLE,
        AccessControlOps::RENOUNCE_ADMIN_ROLE
    );

    pub const GET_EFFECTIVE_WRITERS_STATEMENT: &'static str = formatcp!(
        "
        SELECT account, op_type FROM t_access_control a
        WHERE stream_id = :stream_id AND op_type IN ({}, {}, {}) AND version = (
            SELECT MAX(version) FROM t_access_control b
            WHERE b.stream_id = a.stream_id AND b.account = a.account AND b.op_type IN ({}, {}, {}))
        ORDER BY account",
        AccessControlOps::GRANT_WRITER_ROLE,
        AccessControlOps::REVOKE_WRITER_ROLE,
        AccessControlOps::RENOUNCE_WRITER_ROLE,
        AccessControlOps::GRANT_WRITER_ROLE,
        AccessControlOps::REVOKE_WRITER_ROLE,
        AccessControlOps::RENOUNCE_WRITER_ROLE
    );

    pub const GET_EFFECTIVE_SPECIAL_KEYS_STATEMENT: &'static str = formatcp!(
        "
        SELECT key, op_type FROM t_access_control a
        WHERE stream_id = :stream_id AND op_type IN ({}, {}) AND version = (
            SELECT MAX(version) FROM t_access_control b
            WHERE b.stream_id = a.stream_id AND b.key = a.key AND b.op_type IN ({}, {}))
        ORDER BY key",
        AccessControlOps::SET_KEY_TO_SPECIAL,
        AccessControlOps::SET_KEY_TO_NORMAL,
        AccessControlOps::SET_KEY_TO_SPECIAL,
        AccessControlOps::SET_KEY_TO_NORMAL
    );

    pub const GET_EFFECTIVE_SPECIAL_WRITERS_STATEMENT: &'static str = formatcp!(
        "
        SELECT key, account, op_type FROM t_access_control a
        WHERE stream_id = :stream_id AND op_type IN ({}, {}, {}) AND version = (
            SELECT MAX(version) FROM t_access_control b
            WHERE b.stream_id = a.stream_id AND b.key = a.key AND b.account = a.account AND
                  b.op_type IN ({}, {}, {}))
        ORDER BY key, account",
        AccessControlOps::GRANT_SPECIAL_WRITER_ROLE,
        AccessControlOps::REVOKE_SPECIAL_WRITER_ROLE,
        AccessControlOps::RENOUNCE_SPECIAL_WRITER_ROLE,
        AccessControlOps::GRANT_SPECIAL_WRITER_ROLE,
        AccessControlOps::REVOKE_SPECIAL_WRITER_ROLE,
        AccessControlOps::RENOUNCE_SPECIAL_WRITER_ROLE
    );

    pub const GET_LATEST_ACCESS_CONTROL_SEQ_STATEMENT: &'static str =
        "SELECT MAX(version) FROM t_access_control WHERE stream_id = :stream_id";

    pub const GET_ACCESS_CONTROL_OPS_IN_RANGE_STATEMENT: &'static str = "
        SELECT op_type, key, account, version FROM t_access_control
        WHERE stream_id = :stream_id AND version > :after AND version < :before
        ORDER BY version ASC
    ";

    pub const PUT_STREAM_WRITE_STATEMENT: &'static str = "
        INSERT OR REPLACE INTO
            t_stream (stream_id, key, version, start_index, end_index, created_at, updated_at)
        VALUES
            (:stream_id, :key, :version, :start_index, :end_index,
             COALESCE((SELECT MIN(created_at) FROM t_stream
                       WHERE stream_id = :stream_id AND key = :key), :ts),
             :ts)
    ";

    pub const DELETE_STREAM_WRITE_STATEMENT: &'static str =
        "DELETE FROM t_stream WHERE version > :version";

    pub const DELETE_ALL_STREAM_WRITE_STATEMENT: &'static str = "DELETE FROM t_stream";

    pub const PUT_ACCESS_CONTROL_STATEMENT: &'static str = "
        INSERT OR REPLACE INTO
            t_access_control (stream_id, key, version, account, op_type, operator, created_at, updated_at)
        VALUES
            (:stream_id, :key, :version, :account, :op_type, :operator, :ts, :ts)
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

    pub const GET_STALE_STREAM_KEYS_STATEMENT: &'static str = "
        SELECT key, MAX(version) AS version, start_index, end_index, updated_at FROM
            t_stream
        WHERE
            stream_id = :stream_id AND key > :cursor
        GROUP BY key
        HAVING updated_at <= :cutoff
        ORDER BY key ASC LIMIT :limit
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
            created_at INTEGER,
            updated_at INTEGER,
            PRIMARY KEY (stream_id, key, version)
        ) WITHOUT ROWID
    ";

    pub const CREATE_STREAM_INDEX_STATEMENTS: [&'static str; 3] = [
        "CREATE INDEX IF NOT EXISTS stream_key_idx ON t_stream(stream_id, key)",
        "CREATE INDEX IF NOT EXISTS stream_version_idx ON t_stream(version)",
        "CREATE INDEX IF NOT EXISTS stream_updated_idx ON t_stream(updated_at)",
    ];

    pub const CREATE_ACCESS_CONTROL_TABLE_STATEMENT: &'static str = "
        CREATE TABLE IF NOT EXISTS t_access_control (
            stream_id BLOB NOT NULL,
            key BLOB,
            version INTEGER NOT NULL,
            account BLOB,
            op_type INTEGER NOT NULL,
            operator BLOB NOT NULL,
            created_at INTEGER,
            updated_at INTEGER
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

    pub const CREATE_RENEW_TABLE_STATEMENT: &'static str = "
        CREATE TABLE IF NOT EXISTS t_renew (
            stream_id BLOB NOT NULL,
            key BLOB NOT NULL,
            attempts INTEGER NOT NULL,
            last_attempt_ts INTEGER NOT NULL,
            last_tx_hash BLOB,
            last_error TEXT,
            PRIMARY KEY (stream_id, key)
        ) WITHOUT ROWID
    ";

    pub const UPSERT_RENEW_ATTEMPT_STATEMENT: &'static str = "
        INSERT INTO t_renew (stream_id, key, attempts, last_attempt_ts, last_tx_hash, last_error)
        VALUES (:stream_id, :key, 1, :ts, :tx_hash, :error)
        ON CONFLICT(stream_id, key) DO UPDATE SET
            attempts = attempts + 1, last_attempt_ts = :ts,
            last_tx_hash = :tx_hash, last_error = :error
    ";

    pub const CLEAR_RENEW_ATTEMPT_STATEMENT: &'static str =
        "DELETE FROM t_renew WHERE stream_id = :stream_id AND key = :key";

    pub const GET_RENEW_ATTEMPT_STATEMENT: &'static str = "
        SELECT attempts, last_attempt_ts, last_tx_hash, last_error FROM t_renew
        WHERE stream_id = :stream_id AND key = :key
    ";

    pub const LIST_STUCK_RENEWALS_STATEMENT: &'static str = "
        SELECT stream_id, key, attempts, last_attempt_ts, last_tx_hash, last_error FROM t_renew
        WHERE attempts >= :min_attempts ORDER BY last_attempt_ts ASC LIMIT :limit
    ";

    pub const GET_NULL_TIME_VERSIONS_STATEMENT: &'static str = "
        SELECT DISTINCT version FROM (
            SELECT version FROM t_stream WHERE updated_at IS NULL
            UNION SELECT version FROM t_access_control WHERE updated_at IS NULL
        ) ORDER BY version ASC LIMIT :limit
    ";

    pub const BACKFILL_STREAM_TIME_STATEMENT: &'static str =
        "UPDATE t_stream SET updated_at = :ts, created_at = COALESCE(created_at, :ts) WHERE version = :version AND updated_at IS NULL";

    pub const BACKFILL_ACCESS_CONTROL_TIME_STATEMENT: &'static str =
        "UPDATE t_access_control SET updated_at = :ts, created_at = COALESCE(created_at, :ts) WHERE version = :version AND updated_at IS NULL";
}
