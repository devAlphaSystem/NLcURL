/**
 * Fetches the full Mozilla Public Suffix List and generates a TypeScript data
 * file at `src/cookies/psl-data.ts`. The generated file contains every rule
 * from the official list maintained at https://publicsuffix.org.
 *
 * Run manually whenever the PSL needs updating:
 *   npx tsx scripts/update-psl.ts
 *
 * The generated file is committed to the repository so builds never require
 * a network call. The PSL changes infrequently (~monthly).
 */
import { writeFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { get } from "../src/core/client.js";

const PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat";
const __dirname = dirname(fileURLToPath(import.meta.url));
const OUTPUT = resolve(__dirname, "..", "src", "cookies", "psl-data.ts");

async function main(): Promise<void> {
  console.log(`Fetching PSL from ${PSL_URL} ...`);
  const res = await get(PSL_URL);
  if (res.status < 200 || res.status >= 300) {
    throw new Error(`Failed to fetch PSL: ${res.status} ${res.statusText}`);
  }
  const text = res.text();

  const rules: string[] = [];
  let icannSection = false;

  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();

    if (line === "// ===BEGIN ICANN DOMAINS===") {
      icannSection = true;
      continue;
    }
    if (line === "// ===END ICANN DOMAINS===") {
      icannSection = false;
      continue;
    }
    if (line === "// ===BEGIN PRIVATE DOMAINS===") {
      icannSection = false;
      continue;
    }
    if (line === "// ===END PRIVATE DOMAINS===") {
      continue;
    }

    if (!line || line.startsWith("//")) continue;

    rules.push(line);
  }

  console.log(`Parsed ${rules.length} rules from the Public Suffix List.`);

  const escaped = rules.map((r) => r.replace(/\\/g, "\\\\").replace(/"/g, '\\"'));

  const header = `/**
 * AUTO-GENERATED — DO NOT EDIT MANUALLY.
 *
 * Complete Mozilla Public Suffix List rules.
 * Generated from: ${PSL_URL}
 * Generated on:   ${new Date().toISOString()}
 * Total rules:    ${rules.length}
 *
 * To regenerate: npx tsx scripts/update-psl.ts
 */

// prettier-ignore
export const PSL_RULES: readonly string[] = [
${escaped.map((r) => `  "${r}",`).join("\n")}
];
`;

  writeFileSync(OUTPUT, header, "utf-8");
  console.log(`Wrote ${rules.length} rules to ${OUTPUT}`);
  console.log(`File size: ${(Buffer.byteLength(header) / 1024).toFixed(1)} KB`);
}

main().catch((err) => {
  console.error("Failed to update PSL:", err);
  process.exit(1);
});
