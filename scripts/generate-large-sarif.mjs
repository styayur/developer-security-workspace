import { createWriteStream } from "node:fs";
import { once } from "node:events";
import { finished } from "node:stream/promises";

const count = Number(process.argv[2] ?? 1000);
const destination = process.argv[3] ?? `large-${count}.sarif`;
if (!Number.isSafeInteger(count) || count < 1 || count > 1_000_000) throw new Error("Count must be between 1 and 1,000,000.");
const output = createWriteStream(destination, { flags: "wx" });
const write = async (text) => { if (!output.write(text)) await once(output, "drain"); };
await write('{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Synthetic benchmark","version":"1","rules":[{"id":"benchmark.rule","properties":{"tags":["sast","CWE-89"]}}]}},"results":[');
for (let i = 0; i < count; i++) {
  await write((i ? "," : "") + JSON.stringify({ ruleId: "benchmark.rule", ruleIndex: 0, level: i % 3 ? "warning" : "error", message: { text: `Synthetic finding ${i}` }, fingerprints: { "benchmark/v1": `synthetic-${i}` }, locations: [{ physicalLocation: { artifactLocation: { uri: `src/file-${Math.floor(i / 100)}.ts` }, region: { startLine: i % 100 + 1, startColumn: 1, endColumn: 12 } } }] }));
}
await write("]}]}"); output.end(); await finished(output);
console.log(`Generated ${count.toLocaleString()} synthetic findings: ${destination}`);
