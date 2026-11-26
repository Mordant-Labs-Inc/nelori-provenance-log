#!/usr/bin/env node
// Follows nelori.com and keeps, in this folder, what someone checking a provenance record needs when nelori.com is
// gone or not to be trusted: Nelori's signing keys (keys.json) and each sold work's signed list of versions
// (heads/<work>.json). Hashes and dates only: nothing any record says.
//
//   node mirror.mjs [--dir <folder>] [--from <address>] [--all]
//
// Its rules, which are the point of it:
//   - A key is never added or removed here by this program. keys.json changes by hand only, so taking over
//     nelori.com is not enough to name a new key.
//   - A list of versions is kept only when one of the keys in keys.json signed it.
//   - A list only grows: a version already kept here is never changed or dropped.
// Anything else is refused, said, and ends the run with exit code 1. Node 20 or later, no packages. verify.mjs
// beside it is the checker every copy carries.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const WORK = /^[0-9A-Z]{6,32}$/;
const HASH = /^[0-9a-f]{64}$/;
const START = "1970-01-01T00:00:00.000Z~00000000-0000-0000-0000-000000000000";
const HOUR = 3_600_000;
const WEEK = 7 * 24 * HOUR;

const kept = (file) => {
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch {
    return null;
  }
};
const keep = (file, value) => {
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
};

/** What is wrong with a list of versions as nelori.com gave it, or null when it may be kept. */
async function refusal(checker, head, work, keys, before) {
  if (!head) return "nelori.com did not give it";
  if (typeof head !== "object" || head.format !== checker.FORMAT || head.work !== work) return "it is not a list of this work's versions";
  const { signature, ...body } = head;
  const versions = body.versions;
  if (!Array.isArray(versions) || versions.length === 0 || !versions.every((v, i) => v && v.version === i + 1 && HASH.test(String(v.sha256)) && typeof v.through === "string")) return "its versions are not numbered from 1 with a hash each";
  const bytes = checker.signedBytes("head", checker.sha256Hex(Buffer.from(checker.canonical(body), "utf8")));
  let signed = false;
  for (const k of keys) signed ||= typeof signature === "string" && (await checker.signedBy(k, bytes, signature));
  if (!signed) return "no key in keys.json signed it";
  for (const [i, v] of (before?.versions ?? []).entries()) {
    const now = versions[i];
    if (!now || now.sha256 !== v.sha256 || now.through !== v.through) return `it ${now ? "changes" : "drops"} version ${v.version}, which this log holds as ${v.sha256}`;
  }
  return null;
}

/**
 * One run. `getJson(address)` reads an address as JSON or throws. Returns what was written and every problem
 * found; a problem never stops the works after it from being followed.
 */
export async function mirror({ dir, from = "https://nelori.com", getJson, checker, now = new Date(), all = false }) {
  const said = [];
  const problems = [];
  const state = kept(path.join(dir, "state.json")) ?? {};
  const keys = (kept(path.join(dir, "keys.json"))?.keys ?? []).map((k) => String(k).toLowerCase());
  // state.json is written when something changed, and once a week besides, so the log shows it is still followed
  // (and its host keeps running it) through any stretch with nothing new.
  const stale = !state.checkedAt || now.getTime() - Date.parse(state.checkedAt) >= WEEK;
  const still = (line) => {
    if (stale) keep(path.join(dir, "state.json"), { ...state, checkedAt: now.toISOString() });
    return { said: [line], problems, written: 0 };
  };

  let listed;
  try {
    listed = await getJson(`${from}/.well-known/nelori-provenance.json`);
  } catch {
    // nelori.com down, or provenance not switched on there yet: the log stays as it is, which is what it is for.
    return still(`${from} did not answer, so nothing was changed.`);
  }
  if (keys.length === 0) return { said, problems: ["keys.json holds no key. Add Nelori's public key by hand before the first run."], written: 0 };
  const theirs = Array.isArray(listed?.keys) && listed.format === checker.KEYS_FORMAT ? listed.keys.map((k) => String(k).toLowerCase()) : null;
  if (!theirs) problems.push(`${from} gave something that is not a list of keys.`);
  for (const k of theirs ?? []) if (!keys.includes(k)) problems.push(`${from} lists key ${k}, which keys.json does not hold. If Nelori changed its key, add it to keys.json by hand. If it did not, ${from} is naming a key that is not Nelori's.`);
  for (const k of keys) if (theirs && !theirs.includes(k)) problems.push(`${from} no longer lists key ${k}, which keys.json holds. A key Nelori signed with stays listed.`);

  // The versions made since the last run, read again from an hour before where it stopped: a version is given its
  // time before it is saved, so one saved late sits a little behind the place the last run reached. Once a week,
  // and when asked, every version from the first.
  const full = all || !state.next || !state.fullAt || now.getTime() - Date.parse(state.fullAt) >= WEEK;
  const [time, id] = String(state.next ?? START).split("~");
  let after = full || Number.isNaN(Date.parse(time)) ? START : `${new Date(Math.max(0, Date.parse(time) - HOUR)).toISOString()}~${START.split("~")[1]}`;
  let reached = full ? START : `${time}~${id}`;
  const told = new Map();
  for (const work of state.refused ?? []) if (WORK.test(work)) told.set(work, []);
  try {
    for (;;) {
      const page = await getJson(`${from}/.well-known/nelori-provenance-log.json?after=${encodeURIComponent(after)}`);
      if (!Array.isArray(page?.versions) || typeof page.next !== "string") throw new Error("not a page of versions");
      for (const v of page.versions) {
        if (!WORK.test(String(v.work))) problems.push(`${from} told of a work whose ID is not one: ${JSON.stringify(v.work).slice(0, 80)}.`);
        else told.set(v.work, [...(told.get(v.work) ?? []), v]);
      }
      if (page.next > reached) reached = page.next;
      if (!page.more || page.next === after) break;
      after = page.next;
    }
  } catch {
    return still(`${from} did not give the versions made since the last run, so no list was changed.`);
  }

  let written = 0;
  const refused = [];
  for (const [work, versions] of [...told].sort(([a], [b]) => (a < b ? -1 : 1))) {
    const file = path.join(dir, "heads", `${work}.json`);
    const before = kept(file);
    let head = null;
    try {
      head = await getJson(`${from}/works/${work}/record/head`);
    } catch {
      // Told of a version and not given the list that holds it.
    }
    const why =
      (await refusal(checker, head, work, keys, before)) ??
      versions.map((v) => (head.versions[v.version - 1]?.sha256 === v.sha256 ? null : `it leaves out version ${v.version} (${v.sha256}), which ${from} told this log of`)).find(Boolean) ??
      null;
    if (why) {
      refused.push(work);
      problems.push(`${work}: the list of versions was not kept, because ${why}.`);
    } else if (!before || before.versions.length < head.versions.length) {
      keep(file, head);
      written += 1;
      said.push(`${work}: ${before ? `versions ${before.versions.length + 1} to ${head.versions.length}` : `${head.versions.length} version${head.versions.length === 1 ? "" : "s"}`} kept.`);
    }
  }

  const next = { next: reached, fullAt: full ? now.toISOString() : state.fullAt, refused, checkedAt: now.toISOString() };
  const changed = next.next !== state.next || next.fullAt !== state.fullAt || JSON.stringify(refused) !== JSON.stringify(state.refused ?? []);
  if (changed || written > 0 || stale) keep(path.join(dir, "state.json"), next);
  return { said, problems, written };
}

async function main(argv) {
  const flag = (name) => (argv.includes(name) ? (argv[argv.indexOf(name) + 1] ?? "") : null);
  const checker = await import(new URL("./verify.mjs", import.meta.url).href);
  const getJson = async (address) => {
    const res = await fetch(address, { signal: AbortSignal.timeout(30_000), headers: { "User-Agent": "nelori-provenance-log" } });
    if (!res.ok) throw new Error(`${res.status}`);
    return res.json();
  };
  const result = await mirror({ dir: flag("--dir") ?? path.dirname(new URL(import.meta.url).pathname), from: flag("--from") ?? "https://nelori.com", getJson, checker, all: argv.includes("--all") });
  for (const line of result.said) console.log(line);
  for (const line of result.problems) console.error(`REFUSED ${line}`);
  console.log(`${result.written} list${result.written === 1 ? "" : "s"} of versions written, ${result.problems.length} problem${result.problems.length === 1 ? "" : "s"}.`);
  return result.problems.length > 0 ? 1 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main(process.argv.slice(2)).then((code) => process.exit(code));
