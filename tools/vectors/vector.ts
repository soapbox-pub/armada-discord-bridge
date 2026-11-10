// Copies the fixtures Vector itself produced, which Armada carries, into the
// crate, so the Rust fold is checked against Vector directly and not only
// against Armada's reading of it:
//
//   bun tools/vectors/vector.ts
//
// guild.json and switched.json are whole Communities Vector built through its
// own service code (switched.json is one that moved to ranked roles after it
// had Channels and Roles). roster_fuzz.json is 60 random Control Planes Vector
// built and folded; only each case's unfloored slice is kept, since the bridge
// always folds fresh; channel_fuzz.json likewise. ARMADA points at a checkout of the Armada client.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

const ARMADA = process.env.ARMADA ?? `${homedir()}/Projects/armada`;
const from = join(ARMADA, "src/concord/lib/fixtures/cord25");
const to = join(dirname(new URL(import.meta.url).pathname), "../../crates/concord/tests/vectors/vector");
mkdirSync(to, { recursive: true });

for (const name of ["guild", "switched"]) {
  writeFileSync(join(to, `${name}.json`), JSON.stringify(JSON.parse(readFileSync(join(from, `${name}.json`), "utf8"))));
}
// channel_fuzz.json: random Channel and Category editions (renames, re-filing,
// positions, topics, forks, deletions) from managers and non-managers.
for (const name of ["roster_fuzz", "channel_fuzz"]) {
  const cases = JSON.parse(readFileSync(join(from, `${name}.json`), "utf8"));
  const unfloored = cases.map((c: any) => {
    const slice = c.slices.find((s: any) => !s.floors);
    return { seed: c.seed, community: c.community, scopes: c.scopes, actors: c.actors, events: c.events, served: slice.served, vector: slice.vector };
  });
  writeFileSync(join(to, `${name}.json`), JSON.stringify(unfloored));
}
