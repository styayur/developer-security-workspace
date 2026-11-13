//! SQLite integers are signed 64-bit; reject host-size overflow and corrupt counts.
use rusqlite::{types::Type, Row};

pub fn encode_index(value: usize) -> rusqlite::Result<i64> {
    i64::try_from(value).map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
}

pub fn read_index(row: &Row<'_>, column: usize) -> rusqlite::Result<usize> {
    let value: i64 = row.get(column)?;
    usize::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(column, Type::Integer, Box::new(error))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{params, Connection};

    #[test]
    fn sqlite_counts_round_trip_and_reject_invalid_values() -> rusqlite::Result<()> {
        let db = Connection::open_in_memory()?;
        db.execute_batch("CREATE TABLE counts(value INTEGER);")?;
        let maximum = usize::try_from(i64::MAX).unwrap_or(usize::MAX);
        for value in [0, 1, 1_000_000, maximum] {
            db.execute("INSERT INTO counts VALUES(?1)", [encode_index(value)?])?;
            assert_eq!(
                db.query_row(
                    "SELECT value FROM counts ORDER BY rowid DESC LIMIT 1",
                    [],
                    |row| read_index(row, 0)
                )?,
                value
            );
        }
        for value in [
            rusqlite::types::Value::Integer(-1),
            rusqlite::types::Value::Real(1.5),
            rusqlite::types::Value::Text("invalid".into()),
            rusqlite::types::Value::Null,
        ] {
            db.execute("INSERT INTO counts VALUES(?1)", params![value])?;
            assert!(db
                .query_row(
                    "SELECT value FROM counts ORDER BY rowid DESC LIMIT 1",
                    [],
                    |row| read_index(row, 0)
                )
                .is_err());
        }
        #[cfg(target_pointer_width = "64")]
        assert!(encode_index(usize::MAX).is_err());
        #[cfg(target_pointer_width = "32")]
        assert!(db
            .query_row("SELECT 4294967296", [], |row| read_index(row, 0))
            .is_err());
        Ok(())
    }
}
