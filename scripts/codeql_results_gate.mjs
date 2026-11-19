// SPDX-License-Identifier: AGPL-3.0-only
// Reviewed from styayur/vextessera 710acdee14a7c4bac1834ec60b5b53580444ffac.
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";

const directory = process.argv[2];
assert.ok(directory, "Provide the CodeQL SARIF output directory");
const files = (await readdir(directory)).filter((name) =>
  name.endsWith(".sarif"),
);
assert.ok(files.length, "CodeQL produced no SARIF evidence");
let findings = 0;
for (const file of files) {
  const sarif = JSON.parse(await readFile(`${directory}/${file}`, "utf8"));
  assert.equal(sarif.version, "2.1.0");
  assert.ok(
    Array.isArray(sarif.runs) && sarif.runs.length,
    "Missing analysis run",
  );
  for (const run of sarif.runs) {
    assert.equal(run.tool?.driver?.name, "CodeQL");
    assert.ok(Array.isArray(run.results), "Missing CodeQL results");
    findings += run.results.length;
    for (const result of run.results) {
      process.stdout.write(
        `${result.ruleId}: ${result.message?.text ?? "finding"}\n`,
      );
    }
  }
}
assert.equal(
  findings,
  0,
  "CodeQL findings require review; this gate has no suppressions",
);
process.stdout.write(
  `CODEQL: ${files.length} SARIF file(s), zero findings PASS\n`,
);
