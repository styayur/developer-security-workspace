# Timestamp dependency maintenance

RUSTSEC-2026-0543 marks Chrono unmaintained. DSW used it internally for UTC
strings and elapsed wall-clock durations; no serialized public type contains a
Chrono type. The unused rusqlite `chrono` feature is removed as well.

The maintained `time` 0.3.55 package already present in the desktop dependency
graph now handles RFC3339 parsing and UTC clock readings. The timestamp helper
keeps the existing `+00:00` suffix and Chrono AutoSi fractional precision
(zero, three, six or nine digits). Database schemas and stored values are not
rewritten. Positive and negative offsets are accepted in existing starts.
Durations still truncate to whole milliseconds, clamp a backwards wall clock
to zero, and preserve `None` for malformed starts in normal scan completion
(`0` in the streaming import path, as before).

`timestamps` tests cover offsets, year rollover, fractional precision, malformed
starts and negative/submillisecond durations. The storage regression completes
legacy persisted rows and checks the original start string, optional duration,
future-start clamp and completed timestamp suffix. Existing scanner, streaming,
migration and desktop tests continue to cover their callers. Hosted Linux and
Windows CI are required before merging. Dependency security keeps its existing
audit, unmaintained-advisory, license and source policies.

This change does not dismiss the separate GLib CodeQL findings or claim that
they have been resolved.
