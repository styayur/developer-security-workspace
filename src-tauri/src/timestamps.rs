//! UTC strings remain compatible with persisted Chrono RFC3339 timestamps.
use time::{format_description::well_known::Rfc3339, OffsetDateTime, UtcOffset};

pub fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

pub fn now_rfc3339() -> String {
    format_rfc3339(now())
}

pub fn format_rfc3339(value: OffsetDateTime) -> String {
    let value = value.to_offset(UtcOffset::UTC);
    // Match Chrono's AutoSi representation, including +00:00 and 0/3/6/9 digits.
    let nanos = value.nanosecond();
    let fraction = if nanos == 0 {
        String::new()
    } else if nanos.is_multiple_of(1_000_000) {
        format!(".{:03}", nanos / 1_000_000)
    } else if nanos.is_multiple_of(1_000) {
        format!(".{:06}", nanos / 1_000)
    } else {
        format!(".{nanos:09}")
    };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{fraction}+00:00",
        value.year(),
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute(),
        value.second(),
    )
}

/// Malformed persisted starts remain absent; backwards wall clocks clamp to zero.
pub fn elapsed_milliseconds(start: &str, finished: OffsetDateTime) -> Option<i64> {
    let start = OffsetDateTime::parse(start, &Rfc3339).ok()?;
    Some(
        (finished - start)
            .whole_milliseconds()
            .clamp(0, i64::MAX as i128) as i64,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_strings_keep_utc_offset_and_auto_si_precision() -> Result<(), time::error::Parse> {
        for (legacy, expected) in [
            ("2026-11-19T11:30:00Z", "2026-11-19T11:30:00+00:00"),
            ("2026-11-19T19:30:00+08:00", "2026-11-19T11:30:00+00:00"),
            ("2026-11-19T11:30:00.1Z", "2026-11-19T11:30:00.100+00:00"),
            (
                "2026-11-19T11:30:00.1234Z",
                "2026-11-19T11:30:00.123400+00:00",
            ),
            (
                "2026-11-19T11:30:00.123456789Z",
                "2026-11-19T11:30:00.123456789+00:00",
            ),
            ("2026-01-01T00:30:00+01:00", "2025-12-31T23:30:00+00:00"),
        ] {
            assert_eq!(
                format_rfc3339(OffsetDateTime::parse(legacy, &Rfc3339)?),
                expected
            );
        }
        Ok(())
    }

    #[test]
    fn existing_starts_keep_offset_duration_and_bad_clock_behavior(
    ) -> Result<(), time::error::Parse> {
        let end = OffsetDateTime::parse("2026-11-19T11:30:01.123456Z", &Rfc3339)?;
        for start in ["2026-11-19T11:30:00+00:00", "2026-11-19T19:30:00+08:00"] {
            assert_eq!(elapsed_milliseconds(start, end), Some(1123));
        }
        assert_eq!(
            elapsed_milliseconds("2026-11-19T11:30:01.124Z", end),
            Some(0)
        );
        assert_eq!(
            elapsed_milliseconds("2026-11-19T11:30:01.123Z", end),
            Some(0)
        );
        assert_eq!(elapsed_milliseconds("invalid legacy timestamp", end), None);
        assert_eq!(elapsed_milliseconds("", end), None);
        Ok(())
    }
}
