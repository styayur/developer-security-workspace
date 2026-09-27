# Interactive demo workspace

Choose **Try Demo Workspace**. DSW generates source files locally, imports synthetic fixtures through the real Rust parser and creates two completed SQLite scan runs. Reopening the v2 demo reuses those runs, preserving your triage.

1. Open **SQL data flow** / `javascript.taint.sql-flow` in Findings.
2. Select **Trace**. Choose a thread flow, click a step, use Previous/Next or arrow keys, and follow the highlighted Monaco range across files. Independent paths do not merge.
3. Open **Fix** to inspect the parameterized-query replacement; nothing is applied automatically.
4. Open **Raw** for the redacted result or bounded full run. Open the synthetic secret finding to inspect redaction.
5. Confirm a finding or save a triage note. The decision belongs to its identity across scans.
6. Open **Scan history** and compare the two tutorial scans. Existing findings retain identity, the SCA severity change is Changed, and a synthetic resolved configuration issue is Fixed.

The corpus also includes Bandit JSON-compatible SAST, dependency/SCA and `infra/main.tf` IaC examples. It contains no real secret, deployed infrastructure, real database or executed vulnerable service. Existing source files are not overwritten on reopening; delete/recreate the application demo directory manually only if you deliberately want to reset edited tutorial files.

[Capture a real debugger screenshot](assets/README.md) after completing steps 1–2.
