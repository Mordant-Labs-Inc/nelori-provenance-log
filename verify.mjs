#!/usr/bin/env node
// Checks a Nelori provenance copy from the files in its folder alone. No Nelori account, no packages: Node 18 or later.
//
//   node verify.mjs [folder] [--bitcoin] [--merkle-root <height>:<hex>] [--ask] [--nelori <url or head.json>] [--key <hex, url or file>]
//
// What it checks, and what each check needs, is in README.txt beside it and in docs/architecture/provenance.md.
// Nelori's app uses this same file to read and write timestamp proofs, so the two can't drift apart.
import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

export const FORMAT = "nelori-provenance/1";
/** Nelori's list of the keys it signs with, at `/.well-known/nelori-provenance.json`. */
export const KEYS_FORMAT = "nelori-provenance-keys/1";

/**
 * The two places Nelori publishes its keys and each work's list of versions: its own site, and a public log kept
 * apart from it, which takes a key only by hand and a version only when it adds to the ones before. A key counts
 * as Nelori's when every place that answers lists it, so one place taken over can't name a forger's key.
 */
const LOG = "https://raw.githubusercontent.com/Mordant-Labs-Inc/nelori-provenance-log/main";
export const HOMES = [
  { name: "nelori.com", keys: "https://nelori.com/.well-known/nelori-provenance.json", head: (work) => `https://nelori.com/works/${encodeURIComponent(work)}/record/head` },
  { name: "Nelori's public log", keys: `${LOG}/keys.json`, head: (work) => `${LOG}/heads/${encodeURIComponent(work)}.json` },
];

export const sha256 = (bytes) => createHash("sha256").update(bytes).digest();
export const sha256Hex = (bytes) => sha256(bytes).toString("hex");

/**
 * The one way a value is written before it is hashed: the JSON Canonicalization Scheme, RFC 8785 (keys in UTF-16
 * code unit order, no spaces, strings as ECMAScript writes them, UTF-8), for a value with no number but a whole one.
 * A record holds no other number, and one given here is refused, so any RFC 8785 library writes the same bytes.
 */
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(",")}}`;
  }
  if (typeof value === "number" && !Number.isSafeInteger(value)) throw new Error("Only whole numbers can be written canonically");
  return JSON.stringify(value);
}

/** What the manifest holds for one statement: the SHA-256 of the statement written canonically with its salt. */
export const statementDigest = (entry) => sha256Hex(Buffer.from(canonical({ salt: entry.salt, statement: entry.statement }), "utf8"));

// ---- OpenTimestamps proofs (the detached .ots format, version 1) ----

const OTS_MAGIC = Buffer.from("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294", "hex");
export const BITCOIN_TAG = "0588960d73d71901";
export const PENDING_TAG = "83dfe30d2ef90c8e";
const HASHES = { 0x02: "sha1", 0x03: "ripemd160", 0x08: "sha256" };

function reader(bytes) {
  let at = 0;
  const take = (n) => {
    if (at + n > bytes.length) throw new Error("The timestamp proof ends early");
    at += n;
    return bytes.subarray(at - n, at);
  };
  const varuint = () => {
    let value = 0;
    for (let shift = 0; ; shift += 7) {
      const b = take(1)[0];
      value += (b & 0x7f) * 2 ** shift;
      if (!(b & 0x80)) return value;
      if (shift > 42) throw new Error("A number in the timestamp proof is too long");
    }
  };
  return { take, varuint, varbytes: () => take(varuint()), done: () => at === bytes.length };
}

function writeVaruint(n) {
  const out = [];
  do {
    const b = n % 128;
    n = Math.floor(n / 128);
    out.push(n > 0 ? b | 0x80 : b);
  } while (n > 0);
  return Buffer.from(out);
}
const writeVarbytes = (bytes) => Buffer.concat([writeVaruint(bytes.length), bytes]);

function applyOp(tag, arg, message) {
  if (tag === 0xf0) return Buffer.concat([message, arg]);
  if (tag === 0xf1) return Buffer.concat([arg, message]);
  if (HASHES[tag]) return createHash(HASHES[tag]).update(message).digest();
  throw new Error(`The timestamp proof uses a step this checker doesn't know (0x${tag.toString(16)})`);
}

/**
 * A proof read as a tree. Each node has the bytes it stands for (`message`), the steps that lead on from it, and
 * what vouches for it: a Bitcoin block's height, or a calendar still waiting for one.
 */
function readNode(r, message, depth = 0) {
  if (depth > 256) throw new Error("The timestamp proof is nested too deep");
  const node = { message, attestations: [], steps: [] };
  const one = (tag) => {
    if (tag === 0x00) {
      const kind = r.take(8).toString("hex");
      const payload = Buffer.from(r.varbytes());
      const p = reader(payload);
      if (kind === BITCOIN_TAG) node.attestations.push({ kind: "bitcoin", height: p.varuint() });
      else if (kind === PENDING_TAG) node.attestations.push({ kind: "pending", url: Buffer.from(p.varbytes()).toString("utf8") });
      else node.attestations.push({ kind: "other", tag: kind, payload });
      return;
    }
    const arg = tag === 0xf0 || tag === 0xf1 ? Buffer.from(r.varbytes()) : null;
    node.steps.push({ tag, arg, next: readNode(r, applyOp(tag, arg, message), depth + 1) });
  };
  let tag = r.take(1)[0];
  while (tag === 0xff) {
    one(r.take(1)[0]);
    tag = r.take(1)[0];
  }
  one(tag);
  return node;
}

/** A calendar's answer, or any part of a proof, read from the bytes it starts at. */
export function readTimestamp(bytes, message) {
  const r = reader(Buffer.from(bytes));
  const node = readNode(r, Buffer.from(message));
  if (!r.done()) throw new Error("The timestamp proof has bytes after its end");
  return node;
}

/** A whole .ots file: the SHA-256 it is a proof of, and its tree. */
export function readProof(bytes) {
  const r = reader(Buffer.from(bytes));
  if (!r.take(OTS_MAGIC.length).equals(OTS_MAGIC)) throw new Error("Not an OpenTimestamps proof");
  if (r.varuint() !== 1) throw new Error("An OpenTimestamps proof of a version this checker doesn't know");
  if (r.take(1)[0] !== 0x08) throw new Error("The proof is not of a SHA-256");
  const digest = Buffer.from(r.take(32));
  const tree = readNode(r, digest);
  if (!r.done()) throw new Error("The timestamp proof has bytes after its end");
  return { digest, tree };
}

function writeAttestation(a) {
  const [tag, payload] =
    a.kind === "bitcoin" ? [BITCOIN_TAG, writeVaruint(a.height)] : a.kind === "pending" ? [PENDING_TAG, writeVarbytes(Buffer.from(a.url, "utf8"))] : [a.tag, a.payload];
  return Buffer.concat([Buffer.from([0x00]), Buffer.from(tag, "hex"), writeVarbytes(payload)]);
}

function writeNode(node) {
  const parts = [...node.attestations.map(writeAttestation), ...node.steps.map((s) => Buffer.concat([Buffer.from([s.tag]), s.arg ? writeVarbytes(s.arg) : Buffer.alloc(0), writeNode(s.next)]))];
  if (parts.length === 0) throw new Error("A timestamp proof can't end without anything vouching for it");
  return Buffer.concat(parts.flatMap((part, i) => (i < parts.length - 1 ? [Buffer.from([0xff]), part] : [part])));
}

export const writeProof = (digest, tree) => Buffer.concat([OTS_MAGIC, Buffer.from([0x01, 0x08]), digest, writeNode(tree)]);

/** Everything that vouches for a proof, each with the bytes it vouches for. */
export function attestationsOf(node, found = []) {
  for (const a of node.attestations) found.push({ ...a, message: node.message, node });
  for (const s of node.steps) attestationsOf(s.next, found);
  return found;
}

/** Add a calendar's later answer under the node it answers for. Nothing already there is lost. */
export function mergeInto(node, answer) {
  for (const a of answer.attestations) {
    if (!node.attestations.some((b) => canonical({ ...b, payload: undefined }) === canonical({ ...a, payload: undefined }))) node.attestations.push(a);
  }
  for (const s of answer.steps) {
    const same = node.steps.find((t) => t.tag === s.tag && Buffer.compare(t.arg ?? Buffer.alloc(0), s.arg ?? Buffer.alloc(0)) === 0);
    if (same) mergeInto(same.next, s.next);
    else node.steps.push(s);
  }
}

/** A Bitcoin block's Merkle root as explorers and `bitcoin-cli` print it, from the bytes a proof ends on. */
export const merkleRootHex = (message) => Buffer.from(message).reverse().toString("hex");

// ---- Signatures ----

const ED25519_SPKI = Buffer.from("302a300506032b6570032100", "hex");

/** Whether Nelori's key signed these bytes. The key is 32 bytes of Ed25519, in hex. A browser answers later, so wait for it. */
export function signedBy(publicKeyHex, bytes, signatureHex) {
  try {
    const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI, Buffer.from(publicKeyHex, "hex")]), format: "der", type: "spki" });
    return verifySignature(null, bytes, key, Buffer.from(signatureHex, "hex"));
  } catch {
    return false;
  }
}

/** The bytes a signature is over: what is signed, and the SHA-256 it is about. */
export const signedBytes = (what, digestHex) => Buffer.from(`${FORMAT} ${what} ${digestHex}`, "utf8");

// ---- The check itself ----

const MEDIA_EXT = { "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "application/pdf": "pdf" };
export const evidencePath = (file) => `evidence/${file.sha256}.${MEDIA_EXT[file.mediaType] ?? "bin"}`;

/**
 * The statements a copy shows, read under the headings of Object ID, the international checklist for describing a
 * work so that it can be identified if it is lost or stolen. Each line is the artist's word, from the latest statement
 * that gives it, and `files` are the photographs the artist took of it for the sale. A heading the record says nothing
 * under has no value. Null for a record made before its statements had kinds.
 */
export function objectIdOf(statements) {
  const last = (kind, test = () => true) => statements.filter((s) => s?.kind === kind && test(s)).at(-1) ?? null;
  const f = last("object.described")?.facts;
  if (!f) return null;
  const said = last("object.features_said")?.facts ?? {};
  // The artist's own photographs: at packing, or at a handover in person when it was the artist who took one.
  const taken = (shot) => last("object.photographed", (s) => s.voice === "Artist says" && (s.facts?.set === "packing" || s.facts?.set === "meeting") && s.facts?.shot === shot)?.evidence ?? [];
  const join = (...parts) => parts.filter(Boolean).join(", ") || null;
  return [
    { name: "Type of object", value: f.type ?? null, files: [] },
    { name: "Materials and techniques", value: join(f.medium, f.support), files: [] },
    { name: "Measurements", value: f.height && f.width ? `${f.height} x ${f.width}${f.depth ? ` x ${f.depth}` : ""} ${f.unit}, height by width${f.depth ? " by depth" : ""}` : null, files: [] },
    { name: "Inscriptions and markings", value: said.signed === true ? (said.inscription ? `Signed: ${said.inscription}` : "Signed") : said.signed === false ? "Not signed" : null, files: taken("signature") },
    { name: "Distinguishing features", value: said.condition ? `Condition: ${said.condition}` : null, files: taken("detail") },
    { name: "Title", value: f.title ?? null, files: [] },
    { name: "Subject", value: null, files: [] },
    { name: "Date or period", value: f.madeFrom && f.madeTo && f.madeFrom !== f.madeTo ? `${f.madeFrom} to ${f.madeTo}` : (f.madeFrom ?? f.madeTo ?? null), files: [] },
    { name: "Maker", value: f.artist ?? null, files: [] },
    { name: "Photographs", value: null, files: [...taken("front"), ...taken("back")] },
  ];
}
/** What the pages say above those lines. */
export const OBJECT_ID_LEAD = "The work as its artist described it, under the headings of Object ID, the international checklist for describing a work so that it can be identified if it is lost or stolen. Every line is the artist's word, from the statements below.";

/**
 * Check a copy. `read(name)` gives a file's bytes or null, `list(dir)` the names in a folder. `bitcoin(height)`,
 * when given, answers with a block's Merkle root and time; `head`, when given, is Nelori's current list of versions.
 * `apart` and `asked` are what `askNelori()` found: the keys only one of Nelori's two places lists, and what it has to say.
 * Returns every finding and one verdict: "valid", "incomplete" or "tampered".
 */
export async function checkCopy({ read, list, bitcoin = null, head = null, pinnedKey = null, unreadKeys = null, apart = null, asked = [], how = {} }) {
  const findings = [];
  const say = (level, text) => findings.push({ level, text });
  const result = { verdict: "valid", findings, manifest: null, statements: [], stamp: null, standing: null };
  const fail = (text) => say("tampered", text);
  const missing = (text) => say("incomplete", text);

  const manifestBytes = read("manifest.json");
  if (!manifestBytes) {
    missing("manifest.json is not here. Without it nothing else can be checked.");
    return finish(result);
  }
  const digest = sha256Hex(manifestBytes);
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString("utf8"));
  } catch {
    fail("manifest.json can't be read.");
    return finish(result);
  }
  if (manifest?.format !== FORMAT) {
    fail(`manifest.json is in a format this checker doesn't know: ${String(manifest?.format)}.`);
    return finish(result);
  }
  if (!Array.isArray(manifest.statements)) {
    fail("manifest.json can't be read as the seal of a record: it holds no list of statements.");
    return finish(result);
  }
  result.manifest = { ...manifest, sha256: digest };
  say("ok", `manifest.json is version ${manifest.version} of the record of work ${manifest.work}, SHA-256 ${digest}.`);

  // The statements against the manifest.
  const recordBytes = read("record.json");
  let entries = null;
  if (!recordBytes) missing("record.json is not here, so no statement can be read.");
  else {
    try {
      entries = JSON.parse(recordBytes.toString("utf8")).statements;
    } catch {
      // Told below, with a record.json that parses and holds no list.
    }
    // A record.json with its statements taken out whole is not a copy that shows none.
    if (!Array.isArray(entries)) {
      entries = null;
      fail("record.json can't be read.");
    }
  }
  const bound = new Map();
  if (entries) {
    if (entries.length !== manifest.statements.length) fail(`record.json has ${entries.length} places for statements and the manifest has ${manifest.statements.length}.`);
    else {
      let shown = 0;
      let edited = 0;
      entries.forEach((entry, i) => {
        if (entry === null) return;
        if (statementDigest(entry) !== manifest.statements[i]) {
          edited += 1;
          fail(`Statement ${i + 1} (${entry.statement?.id ?? "no id"}) is not the one the manifest holds: it was changed after the record was made.`);
          return;
        }
        shown += 1;
        result.statements.push(entry.statement);
        for (const file of entry.statement.evidence ?? []) bound.set(file.sha256, file);
      });
      const withheld = entries.length - shown - edited;
      say("ok", `${shown} of ${entries.length} statements are shown here and match the manifest.`);
      if (withheld > 0) say("note", `${withheld} statements are withheld from this copy. They are part of the record, and the manifest holds a salted SHA-256 of each, which gives nothing of what they say.`);
    }
  }

  // Nelori's signatures.
  const sigBytes = read("manifest.sig.json");
  let key = null;
  // Asked to hold the signature to Nelori's keys, and they could not be read: the copy's own word is not enough.
  if (unreadKeys) missing(`Nelori's keys could not be read from ${unreadKeys}, so nothing here holds the signature to Nelori's key.`);
  if (!sigBytes) missing("manifest.sig.json is not here, so nothing shows that Nelori made this record.");
  else {
    const sig = parsed(sigBytes) ?? {};
    if (typeof sig.publicKey !== "string" || typeof sig.signature !== "string") fail("manifest.sig.json can't be read as a signature.");
    else if (!(await signedBy(sig.publicKey, signedBytes("manifest", digest), sig.signature))) fail("The signature in manifest.sig.json is not over this manifest.");
    else if (pinnedKey && ![pinnedKey].flat().some((k) => String(k).toLowerCase() === sig.publicKey)) fail(`The manifest is signed, but by key ${sig.publicKey}, ${how.signed ? "which Nelori does not list as its own" : "not the key you gave"}.`);
    else if (apart?.[sig.publicKey]) {
      // One place may have been taken over, or a new key not yet written in the other: either way, not yet Nelori's word.
      key = sig.publicKey;
      missing(`The key that signed this copy is listed at ${apart[sig.publicKey].at} and not at ${apart[sig.publicKey].not}. Until both list it, nothing here holds the signature to Nelori's key.`);
    } else {
      key = sig.publicKey;
      say("ok", how.signed ? how.signed : pinnedKey ? "Signed by the Nelori key you gave." : `Signed by key ${sig.publicKey}. Check that this is Nelori's key from a place other than this copy, or ${how.key ?? "pass it with --key"}.`);
    }
  }

  // The files, against the statements and against what the copy was issued with.
  const copyBytes = read("copy.json");
  let issued = null;
  if (!copyBytes) missing("copy.json is not here, so nothing shows which statements and files this copy was issued with, or whether any was taken out since.");
  else {
    const { signature, ...body } = parsed(copyBytes) ?? {};
    if (typeof signature !== "string" || !Array.isArray(body.files) || !Array.isArray(body.disclosed)) fail("copy.json can't be read as what this copy was issued with.");
    else if (body.manifest !== digest) fail("copy.json is for another version of the record.");
    else if (!key || !(await signedBy(key, signedBytes("copy", sha256Hex(Buffer.from(canonical(body), "utf8"))), signature))) fail("copy.json is not signed by the key that signed the manifest.");
    else {
      issued = body;
      say("ok", `This copy was issued on ${body.issuedAt} as ${body.kind === "full" ? "a full copy for the people in the sale" : "a copy to share"}, with ${body.files.length} files of evidence.`);
      if (entries) {
        const shownIds = new Set(result.statements.map((s) => s.id));
        const gone = body.disclosed.filter((id) => !shownIds.has(id));
        if (gone.length > 0 && !findings.some((f) => f.level === "tampered")) missing(`${gone.length} statements this copy was issued with are no longer shown in record.json.`);
      }
    }
  }
  const present = new Set(list("evidence"));
  const issuedFiles = new Set((issued?.files ?? []).map((f) => f.sha256));
  let matched = 0;
  let withheldFiles = 0;
  for (const file of bound.values()) {
    const name = evidencePath(file);
    const bytes = read(name);
    present.delete(path.basename(name));
    if (!bytes) {
      if (issuedFiles.has(file.sha256)) missing(`${name} was issued with this copy and is not here.`);
      else withheldFiles += 1;
    } else if (sha256Hex(bytes) !== file.sha256) fail(`${name} is not the file the record names: its SHA-256 is ${sha256Hex(bytes)}.`);
    else matched += 1;
  }
  if (bound.size > 0) say("ok", `${matched} of ${bound.size} files the shown statements name are here and match byte for byte.`);
  if (withheldFiles > 0) say("note", `${withheldFiles} files the statements name were not issued with this copy. The record holds the SHA-256 of each, so a file shown later can be checked against it.`);
  for (const extra of present) say("note", `evidence/${extra} is not named by any statement shown here. It is not part of the record.`);
  // The account to read, which says the same statements in a page.
  for (const page of issued?.pages ?? []) {
    const bytes = read(page.path);
    // The account is the statements again in a page; any other file describes the record and is no part of it.
    const account = String(page.path).endsWith(".html");
    if (!bytes) say("note", account ? `${page.path}, the account to read, is not here. The statements below are the same ones.` : `${page.path} was issued with this copy and is not here. It describes the record and is not part of it.`);
    else if (sha256Hex(bytes) !== page.sha256) fail(account ? `${page.path} is not the page this copy was issued with. Read the statements this checker prints instead.` : `${page.path} is not the file this copy was issued with.`);
    else say("ok", `${page.path} is the ${account ? "page" : "file"} this copy was issued with.`);
  }

  // The timestamp.
  const otsBytes = read("manifest.json.ots");
  if (!otsBytes) missing("manifest.json.ots is not here, so nothing outside Nelori shows when this record existed.");
  else {
    let proof = null;
    try {
      proof = readProof(otsBytes);
    } catch (e) {
      fail(`manifest.json.ots can't be read: ${e.message}`);
    }
    if (proof && proof.digest.toString("hex") !== digest) fail("manifest.json.ots is a timestamp of other bytes, not of this manifest.");
    else if (proof) {
      const all = attestationsOf(proof.tree);
      const blocks = all.filter((a) => a.kind === "bitcoin");
      result.stamp = { blocks: blocks.map((b) => ({ height: b.height, merkleRoot: merkleRootHex(b.message) })), pending: all.filter((a) => a.kind === "pending").map((a) => a.url), confirmed: null };
      if (blocks.length === 0) missing(`The timestamp is not in a Bitcoin block yet. It waits at ${result.stamp.pending.join(", ") || "no calendar"}. A later copy carries the finished proof.`);
      else {
        for (const b of result.stamp.blocks) say("ok", `The timestamp proof leads from this manifest to Merkle root ${b.merkleRoot}, which it says is Bitcoin block ${b.height}'s.`);
        if (!bitcoin) say("note", `Not checked against Bitcoin here. ${how.bitcoin ?? "Run with --bitcoin, or look up the block yourself and pass --merkle-root <height>:<hex>."}`);
        else {
          for (const b of result.stamp.blocks) {
            const block = await bitcoin(b.height);
            if (!block) say("note", `Bitcoin block ${b.height} could not be looked up.`);
            else if (block.merkleRoot !== b.merkleRoot) fail(`Bitcoin block ${b.height} has Merkle root ${block.merkleRoot}, not the one the proof leads to.`);
            else {
              result.stamp.confirmed = { height: b.height, time: block.time ?? null, source: block.source };
              say("ok", `Bitcoin block ${b.height} has that Merkle root (${block.source}). ${block.time ? `This record existed by ${block.time}.` : "This record existed when that block was mined."}`);
            }
          }
          if (!result.stamp.confirmed && !findings.some((f) => f.level === "tampered")) missing("No Bitcoin block could be looked up, so the timestamp is not confirmed.");
        }
      }
    }
  }

  // Where this version stands among Nelori's.
  if (head) {
    const body = head;
    // After a change of key the list is signed with the newer key, which the keys given (with --key) still name.
    // A key only one of Nelori's two places lists signs no list here either.
    const headKeys = (key ? [key, ...(pinnedKey ? [pinnedKey].flat().map((k) => String(k).toLowerCase()) : [])] : []).filter((k) => !apart?.[k]);
    const headSigned = await listSignedBy(head, headKeys);
    if (!headSigned) say("note", `Nelori's current list of versions is not signed by the key that signed this copy${pinnedKey ? " or a key you gave" : ""}, so it was not used.`);
    else if (body.work !== manifest.work) say("note", "The list of versions given is for another work.");
    else {
      const at = body.versions.findIndex((v) => v.sha256 === digest);
      const last = body.versions[body.versions.length - 1];
      // A list kept from before this version was made can't hold it, and says nothing of it.
      if (at < 0 && String(body.asOf) < String(manifest.madeAt)) missing(`The list of versions given is as of ${body.asOf}, before this version was made (${manifest.madeAt}), so it can't place it. Ask Nelori for today's list.`);
      else if (at < 0) fail("Nelori's current list of versions doesn't hold this manifest. Nelori didn't issue it.");
      else if (at === body.versions.length - 1) {
        result.standing = "current";
        say("ok", `As of ${body.asOf}, this is the latest version Nelori holds.`);
      } else {
        result.standing = "older";
        say("note", `This is a true earlier version. Nelori has made ${body.versions.length - 1 - at} since, the latest (version ${last.version}) through ${last.through}. What changed is in a newer copy.`);
      }
    }
  }
  findings.push(...asked);
  return finish(result);
}

/** Whether one of these keys signed this list of versions. A list that can't be read as one is signed by nobody. */
async function listSignedBy(head, keys) {
  try {
    const { signature, ...body } = head;
    if (typeof signature !== "string") return false;
    const bytes = signedBytes("head", sha256Hex(Buffer.from(canonical(body), "utf8")));
    for (const k of keys) if (await signedBy(k, bytes, signature)) return true;
  } catch {
    // A number that is not whole, or a signature that is not one: nothing Nelori signs holds either.
  }
  return false;
}

const keysOf = (listed) => (listed?.format === KEYS_FORMAT && Array.isArray(listed.keys) && listed.keys.length > 0 && listed.keys.every((k) => typeof k === "string") ? listed.keys.map((k) => k.toLowerCase()) : null);
const versionsOf = (head) => (head && typeof head === "object" && Array.isArray(head.versions) && head.versions.every((v) => v && typeof v.sha256 === "string") ? head.versions : null);

/**
 * Ask Nelori's two places for its keys and for a work's list of versions, and give `checkCopy` what they say.
 * `getJson(address)` reads an address as JSON or throws. A place that doesn't answer is named and the other is
 * used; two that answer must agree: a key only one lists is not yet Nelori's, and two lists of versions where
 * neither carries on from the other are not used.
 */
export async function askNelori(work, getJson, homes = HOMES) {
  const asked = [];
  const read = async (address) => {
    try {
      return await getJson(address);
    } catch {
      return null;
    }
  };
  const answers = await Promise.all(homes.map(async (home) => ({ home, keys: keysOf(await read(home.keys)), head: work ? await read(home.head(work)) : null })));

  const listing = answers.filter((a) => a.keys);
  let pinnedKey = null;
  let unreadKeys = null;
  let apart = null;
  if (listing.length === 0) unreadKeys = homes.map((h) => h.keys).join(" or ");
  else {
    pinnedKey = [...new Set(listing.flatMap((a) => a.keys))];
    apart = {};
    for (const k of pinnedKey) {
      const not = listing.find((a) => !a.keys.includes(k));
      if (not) apart[k] = { at: listing.find((a) => a.keys.includes(k)).home.name, not: not.home.name };
    }
    for (const a of answers) if (!a.keys) asked.push({ level: "note", text: `Nelori's keys could not be read from ${a.home.name}, so they are as ${listing.map((l) => l.home.name).join(" and ")} lists them.` });
  }

  // A list counts when a key both places hold signed it, so a place taken over can't put the other's list in doubt
  // with one of its own. With no key read, the copy's own key is what `checkCopy` holds the list to.
  const agreed = (pinnedKey ?? []).filter((k) => !apart[k]);
  const lists = [];
  let unsigned = false;
  for (const a of answers) {
    if (!versionsOf(a.head)) continue;
    const signedByNelori = !pinnedKey || (a.head.work === work && (await listSignedBy(a.head, agreed)));
    if (signedByNelori) lists.push(a);
    else unsigned = true;
    if (!signedByNelori) asked.push({ level: "note", text: `The list of versions ${a.home.name} gave is not signed by a key ${listing.length > 1 ? "both places list" : `${listing[0].home.name} lists`} as Nelori's, so it was not used.` });
  }
  lists.sort((a, b) => b.head.versions.length - a.head.versions.length);
  let head = null;
  if (lists.length === 0) asked.push({ level: "note", text: `${unsigned ? "No list of versions signed by Nelori was given" : "Nelori's list of versions could not be read"}, so whether this is its latest version can't be told.` });
  else {
    const [longest, ...rest] = lists;
    // The log follows nelori.com, so it may be a version or two behind. A list that leaves out or changes what the other holds is neither's to trust.
    const carriesOn = rest.every((r) => r.head.versions.every((v, i) => longest.head.versions[i].sha256 === v.sha256 && longest.head.versions[i].version === v.version));
    if (!carriesOn) asked.push({ level: "incomplete", text: `${lists.map((l) => l.home.name).join(" and ")} disagree about this work's versions, so neither list was used and whether this is the latest version can't be told.` });
    else {
      head = longest.head;
      const none = answers.filter((a) => !versionsOf(a.head));
      if (none.length > 0) asked.push({ level: "note", text: `The list of versions is ${longest.home.name}'s alone: ${none.map((a) => a.home.name).join(" and ")} gave none.` });
    }
  }
  const signed = pinnedKey ? `Signed by a key that ${listing.map((l) => l.home.name).join(" and ")} ${listing.length > 1 ? "both list" : "lists"} as Nelori's.` : null;
  return { pinnedKey, unreadKeys, apart, head, asked, signed };
}

/** A file's JSON, or null when it isn't JSON: a file cut short is a finding, never a crash. */
function parsed(bytes) {
  try {
    const value = JSON.parse(bytes.toString("utf8"));
    return value && typeof value === "object" ? value : null;
  } catch {
    return null;
  }
}

function finish(result) {
  result.verdict = result.findings.some((f) => f.level === "tampered") ? "tampered" : result.findings.some((f) => f.level === "incomplete") ? "incomplete" : "valid";
  return result;
}

const EXPLORERS = [
  { name: "blockstream.info", hash: (h) => `https://blockstream.info/api/block-height/${h}`, block: (hash) => `https://blockstream.info/api/block/${hash}` },
  { name: "mempool.space", hash: (h) => `https://mempool.space/api/block-height/${h}`, block: (hash) => `https://mempool.space/api/block/${hash}` },
];

/** A block's Merkle root as two public explorers give it. They must agree. */
export async function lookUpBlock(height) {
  const seen = [];
  for (const e of EXPLORERS) {
    try {
      const answer = async (url) => {
        const res = await fetch(url, { signal: AbortSignal.timeout(15_000) });
        if (!res.ok) throw new Error(`${res.status}`);
        return res;
      };
      const hash = (await (await answer(e.hash(height))).text()).trim();
      const block = await (await answer(e.block(hash))).json();
      seen.push({ source: e.name, merkleRoot: block.merkle_root, time: new Date(block.timestamp * 1000).toISOString() });
    } catch {
      // One explorer being down is not a finding.
    }
  }
  if (seen.length === 0) return null;
  // Two explorers that disagree say nothing about the copy, so neither answer is used.
  if (seen.some((s) => s.merkleRoot !== seen[0].merkleRoot)) return null;
  return { source: seen.map((s) => s.source).join(" and "), merkleRoot: seen[0].merkleRoot, time: seen[0].time };
}

export const VERDICT = {
  valid: "VALID. Every file here is the one the record names, and the record is the one Nelori signed.",
  incomplete: "INCOMPLETE. Nothing here was changed, but something this check needs is missing. See above.",
  tampered: "TAMPERED. Something here is not what the record was made with. See above.",
};

async function main(argv) {
  const flag = (name) => {
    const i = argv.indexOf(name);
    return i < 0 ? null : (argv[i + 1] ?? "");
  };
  const valued = new Set(["--merkle-root", "--nelori", "--key"]);
  const dir = argv.find((a, i) => !a.startsWith("--") && !valued.has(argv[i - 1])) ?? ".";
  const read = (name) => (existsSync(path.join(dir, name)) ? readFileSync(path.join(dir, name)) : null);
  const list = (name) => (existsSync(path.join(dir, name)) ? readdirSync(path.join(dir, name)) : []);
  const given = flag("--merkle-root");
  const bitcoin = given
    ? async (height) => {
        const [h, root] = given.split(":");
        return String(height) === h && /^[0-9a-fA-F]{64}$/.test(root ?? "") ? { merkleRoot: root.toLowerCase(), time: null, source: "as you gave it" } : null;
      }
    : argv.includes("--bitcoin")
      ? lookUpBlock
      : null;
  let head = null;
  let apart = null;
  let asked = [];
  let signed = null;
  const from = flag("--nelori");
  if (from !== null) {
    try {
      head = /^https?:/.test(from) ? await (await fetch(from)).json() : JSON.parse(readFileSync(from, "utf8"));
    } catch {
      console.log(`Nelori's list of versions could not be read from ${from}.`);
    }
  }
  // The key as hex, or Nelori's own list of its keys, from its address or a file kept from it.
  let pinnedKey = flag("--key");
  let unreadKeys = null;
  if (pinnedKey !== null && !/^[0-9a-f]{64}$/i.test(pinnedKey)) {
    const from = pinnedKey;
    try {
      const listed = /^https?:/.test(from) ? await (await fetch(from)).json() : JSON.parse(readFileSync(from, "utf8"));
      if (listed?.format !== KEYS_FORMAT || !Array.isArray(listed.keys) || listed.keys.length === 0) throw new Error("not a list of keys");
      pinnedKey = listed.keys;
    } catch {
      unreadKeys = from || "the place you gave";
      pinnedKey = null;
    }
  }
  // Or ask both of Nelori's places for its keys and its list of versions, which is what the page's "Ask Nelori" does.
  if (argv.includes("--ask")) {
    const getJson = async (address) => {
      const res = await fetch(address, { signal: AbortSignal.timeout(15_000) });
      if (!res.ok) throw new Error(`${res.status}`);
      return res.json();
    };
    ({ pinnedKey, unreadKeys, apart, head, asked, signed } = await askNelori(parsed(read("manifest.json") ?? Buffer.from(""))?.work ?? null, getJson));
  }
  const result = await checkCopy({ read, list, bitcoin, head, pinnedKey, unreadKeys, apart, asked, how: signed ? { signed } : {} });
  const mark = { ok: "  ok   ", note: "  note ", incomplete: "  GAP  ", tampered: "  FAIL " };
  for (const f of result.findings) console.log(mark[f.level] + f.text);
  if (result.manifest) {
    console.log("");
    console.log(`This copy holds the record through ${result.manifest.through}. It says nothing about anything after.`);
    if (!result.standing) console.log("Whether Nelori has made a newer version since can't be told from these files. Run with --ask to ask.");
  }
  if (result.verdict !== "tampered" && result.statements.length > 0 && !argv.includes("--quiet")) {
    console.log("");
    for (const s of result.statements) console.log(`  ${(s.occurredAt ?? s.recordedAt).slice(0, 10)}  [${s.about}] ${s.voice}: ${s.text}`);
  }
  console.log("");
  console.log(`RESULT: ${VERDICT[result.verdict]}`);
  return result.verdict === "valid" ? 0 : result.verdict === "incomplete" ? 3 : 2;
}

// Run as a command, and not when verify.html beside it loads this file in a browser.
if (typeof process !== "undefined" && process.argv?.[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).then((code) => process.exit(code));
}
