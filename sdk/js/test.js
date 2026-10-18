"use strict";

// Minimal dependency-free test (node test.js) — asserts the header/URL helpers.
const assert = require("assert");
const tf = require("./index.js");

assert.strictEqual(tf.gatewayUrl("http://x:4100/"), "http://x:4100");
assert.strictEqual(tf.messagesUrl("http://x:4100"), "http://x:4100/v1/messages");

const h = tf.runHeaders("run-42", {
  budgetUsd: 5,
  taskType: "chat",
  parentRunId: "run-1",
  tags: { team: "core", env: "dev" },
});
assert.strictEqual(h["X-Fuse-Run-Id"], "run-42");
assert.strictEqual(h["X-Fuse-Budget-Usd"], "5");
assert.strictEqual(h["X-Fuse-Task-Type"], "chat");
assert.strictEqual(h["X-Fuse-Parent-Run-Id"], "run-1");
assert.strictEqual(h["X-Fuse-Tags"], "team=core,env=dev");

// runId-only → just the id header.
assert.deepStrictEqual(tf.runHeaders("solo"), { "X-Fuse-Run-Id": "solo" });

// The OpenAI door: the chat completions URL and the base URL an OpenAI client takes.
assert.strictEqual(tf.chatCompletionsUrl("http://x:4100/"), "http://x:4100/v1/chat/completions");
assert.strictEqual(tf.openaiBaseUrl("http://x:4100"), "http://x:4100/v1");
assert.strictEqual(tf.VERSION, "1.0.1");

console.log("ok - tokenfuse js sdk");

// ---- The agent token helper (wave 1 T5). Each test is bound to a scenario of
// features/the-sdk-holds-an-agent-token.feature under the same name as the
// Python test in sdk/python/tests/test_agent.py. The stub vouchryx and the stub
// door check the wire contracts (RFC 6749 2.3.1, RFC 7523, RFC 9449 4.2, 8, 9)
// with node:crypto's own verifier, not with the helper's signing path.

const crypto = require("node:crypto");
const { createAgentFetch, AgentTokenError } = require("./index.js");

const ISSUER = "https://vouchryx.example";
const DOOR = "https://door.example";
const AGENT = "agent://acme/triage";
const SECRET = "s3cr3t+key:/with-chars";
const JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

const unb64 = (text) => Buffer.from(text, "base64url");
const athOf = (token) => crypto.createHash("sha256").update(token, "ascii").digest("base64url");

function verifyCompact(compact) {
  const [head, body, sig] = compact.split(".");
  const header = JSON.parse(unb64(head).toString("utf8"));
  const payload = JSON.parse(unb64(body).toString("utf8"));
  const publicKey = crypto.createPublicKey({ key: header.jwk, format: "jwk" });
  const ok = crypto.verify(
    "sha256",
    Buffer.from(`${head}.${body}`, "ascii"),
    { key: publicKey, dsaEncoding: "ieee-p1363" },
    unb64(sig),
  );
  if (!ok) throw new Error("bad signature");
  return { header, payload };
}

function plain(res) {
  return res;
}

class StubVouchryx {
  constructor() {
    this.clientSecret = SECRET;
    this.issued = new Set();
    this.requests = [];
    this.basicSeen = [];
    this.assertions = [];
    this.tokenNonceChallenges = [];
    this.alwaysChallengeToken = false;
    this.expectedTokenNonce = null;
    this.expiresIn = 300;
    this.lastToken = null;
  }

  handle(req) {
    const form = Object.fromEntries(new URLSearchParams(req.body));
    const record = { form, headers: req.headers, nonce: null };
    this.requests.push(record);
    const proof = req.headers.dpop || "";
    if (!proof) return json(400, { error: "invalid_grant" });
    let payload;
    try {
      payload = verifyCompact(proof).payload;
    } catch {
      return json(400, { error: "invalid_grant" });
    }
    record.nonce = payload.nonce ?? null;
    if (payload.htm !== "POST" || payload.htu !== `${ISSUER}/v1/token` || "ath" in payload) {
      return json(400, { error: "invalid_grant" });
    }

    let challenge = null;
    if (this.tokenNonceChallenges.length) {
      challenge = this.tokenNonceChallenges.shift();
      this.expectedTokenNonce = challenge;
    } else if (this.alwaysChallengeToken) {
      challenge = `v-n${this.requests.length}`;
      this.expectedTokenNonce = challenge;
    } else if (this.expectedTokenNonce !== null && payload.nonce !== this.expectedTokenNonce) {
      challenge = this.expectedTokenNonce;
    }
    if (challenge !== null) {
      return json(400, { error: "use_dpop_nonce" }, { "DPoP-Nonce": challenge });
    }

    if (form.grant_type !== "client_credentials") {
      return json(400, { error: "unsupported_grant_type" });
    }
    if ("client_assertion" in form) {
      this.assertions.push(form.client_assertion);
      if (form.client_assertion_type !== JWT_BEARER || !form.client_assertion.startsWith("wl-")) {
        return json(401, { error: "invalid_client" });
      }
    } else {
      const auth = req.headers.authorization || "";
      if (!auth.startsWith("Basic ")) {
        return json(401, { error: "invalid_client" }, { "WWW-Authenticate": "Basic" });
      }
      const decoded = Buffer.from(auth.slice("Basic ".length), "base64").toString("utf8");
      this.basicSeen.push(decoded);
      const cut = decoded.indexOf(":");
      const clientId = decodeURIComponent(decoded.slice(0, cut));
      const secret = decodeURIComponent(decoded.slice(cut + 1));
      if (clientId !== AGENT || secret !== this.clientSecret) {
        return json(401, { error: "invalid_client" });
      }
    }

    const token = `tok-${this.issued.size + 1}-${crypto.randomBytes(8).toString("hex")}`;
    this.issued.add(token);
    this.lastToken = token;
    return json(200, { access_token: token, token_type: "DPoP", expires_in: this.expiresIn });
  }
}

class StubDoor {
  constructor(vouchryx) {
    this.vouchryx = vouchryx;
    this.nonce = null;
    this.rotations = [];
    this.alwaysChallenge = false;
    this.refuseAll = false;
    this.proofs = [];
    this.refusals = [];
    this.requests = 0;
    this.challenges = 0;
    this.seenJtis = new Set();
  }

  handle(req) {
    this.requests += 1;
    const auth = req.headers.authorization || "";
    const proof = req.headers.dpop || "";
    if (this.refuseAll || !auth.startsWith("DPoP ") || !proof) {
      return json(401, { error: "invalid_token" });
    }
    const token = auth.slice("DPoP ".length);
    let verified;
    try {
      verified = verifyCompact(proof);
    } catch (err) {
      this.refusals.push(`signature: ${err.message}`);
      return json(401, { error: "invalid_dpop_proof" });
    }
    const { header, payload } = verified;
    this.proofs.push({
      htm: payload.htm,
      htu: payload.htu,
      ath: payload.ath,
      jti: payload.jti,
      iat: payload.iat,
      nonce: payload.nonce ?? null,
      token,
    });
    const problems = [];
    if ("d" in header.jwk) problems.push("a private member in the proof's jwk");
    if (payload.htm !== req.method) problems.push("htm");
    if (payload.htu !== req.url.split("?")[0]) problems.push("htu");
    if (payload.ath !== athOf(token)) problems.push("ath");
    if (unb64(payload.jti).length < 12) problems.push("jti shorter than 96 bits");
    if (this.seenJtis.has(payload.jti)) problems.push("jti reused");
    this.seenJtis.add(payload.jti);
    if (Math.abs(Date.now() / 1000 - payload.iat) > 60) problems.push("iat outside the window");
    if (problems.length) {
      this.refusals.push(problems);
      return json(401, { error: "invalid_dpop_proof" });
    }
    if (!this.vouchryx.issued.has(token)) return json(401, { error: "invalid_token" });
    if (this.alwaysChallenge || (this.nonce !== null && payload.nonce !== this.nonce)) {
      this.challenges += 1;
      if (this.alwaysChallenge) this.nonce = `door-n${this.challenges}`;
      return json(
        401,
        { error: "use_dpop_nonce" },
        { "WWW-Authenticate": 'DPoP error="use_dpop_nonce"', "DPoP-Nonce": this.nonce },
      );
    }
    const headers = {};
    if (this.rotations.length) {
      this.nonce = this.rotations.shift();
      headers["DPoP-Nonce"] = this.nonce;
    }
    return json(200, { ok: true }, headers);
  }
}

function json(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

// A fetch that routes the two stub servers by host, as the helper's own fetch sees them.
function stubFetch(vouchryx, door) {
  return async (url, init = {}) => {
    const target = new URL(String(url));
    const headers = {};
    for (const [k, v] of Object.entries(init.headers || {})) headers[k.toLowerCase()] = String(v);
    const req = {
      method: (init.method || "GET").toUpperCase(),
      url: target.toString(),
      headers,
      body: init.body == null ? "" : String(init.body),
    };
    if (target.host === "vouchryx.example") return vouchryx.handle(req);
    if (target.host === "door.example") return door.handle(req);
    throw new Error(`no stub for ${target.host}`);
  };
}

async function generateKeyPem(namedCurve = "prime256v1") {
  const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve });
  return privateKey.export({ type: "pkcs8", format: "pem" });
}

function clockFrom(start) {
  const clock = { ms: start };
  clock.now = () => clock.ms;
  return clock;
}

function wire(vouchryx, door, clock, pem, extra = {}) {
  const fetchImpl = stubFetch(vouchryx, door);
  const doorFetch = createAgentFetch({
    issuer: ISSUER,
    key: pem,
    audience: undefined,
    fetch: fetchImpl,
    now: clock.now,
    ...extra,
  });
  return doorFetch;
}

function enrolled({ vouchryx = new StubVouchryx(), doorNonce = null } = {}) {
  return generateKeyPem().then((pem) => {
    const door = new StubDoor(vouchryx);
    door.nonce = doorNonce;
    const clock = clockFrom(1_000_000);
    const agentFetch = wire(vouchryx, door, clock, pem, { clientId: AGENT, clientSecret: SECRET });
    return { agentFetch, vouchryx, door, clock, pem };
  });
}

async function test_fetches_a_token_and_sends_it_with_a_fresh_proof() {
  const { agentFetch, vouchryx, door } = await enrolled();
  for (let i = 0; i < 2; i += 1) {
    assert.strictEqual((await agentFetch(`${DOOR}/v1/messages`)).status, 200);
  }
  assert.strictEqual(vouchryx.requests.length, 1);
  assert.deepStrictEqual(door.refusals, []);
  assert.strictEqual(door.proofs.length, 2);
  assert.notStrictEqual(door.proofs[0].jti, door.proofs[1].jti);
  assert.deepStrictEqual(new Set(door.proofs.map((p) => p.token)), new Set([vouchryx.lastToken]));
}

async function test_refreshes_at_eighty_percent_of_the_lifetime() {
  const { agentFetch, vouchryx, clock } = await enrolled();
  await agentFetch(`${DOOR}/v1/messages`);
  clock.ms = 1_000_000 + 239_000;
  await agentFetch(`${DOOR}/v1/messages`);
  assert.strictEqual(vouchryx.requests.length, 1);
  clock.ms = 1_000_000 + 240_000;
  await agentFetch(`${DOOR}/v1/messages`);
  assert.strictEqual(vouchryx.requests.length, 2);
}

async function test_each_proof_names_its_request_and_its_token() {
  const { agentFetch, vouchryx, door } = await enrolled();
  assert.strictEqual((await agentFetch(`${DOOR}/v1/messages?stream=1&x=2`)).status, 200);
  const seen = door.proofs[door.proofs.length - 1];
  assert.strictEqual(seen.htm, "GET");
  assert.strictEqual(seen.htu, `${DOOR}/v1/messages`);
  assert.strictEqual(seen.ath, athOf(vouchryx.lastToken));
  assert.ok(unb64(seen.jti).length >= 12);
  assert.ok(Math.abs(seen.iat - Date.now() / 1000) < 60);
  assert.deepStrictEqual(door.refusals, []);
}

async function test_a_nonce_challenge_is_retried_once_with_the_nonce() {
  const { agentFetch, door } = await enrolled({ doorNonce: "door-nonce-1" });
  assert.strictEqual((await agentFetch(`${DOOR}/v1/messages`)).status, 200);
  assert.strictEqual(door.challenges, 1);
  assert.strictEqual(door.proofs.length, 2);
  assert.strictEqual(door.proofs[0].nonce, null);
  assert.strictEqual(door.proofs[1].nonce, "door-nonce-1");
  assert.deepStrictEqual(door.refusals, []);
}

async function test_the_newest_nonce_is_used_next() {
  const { agentFetch, door } = await enrolled({ doorNonce: "door-nonce-1" });
  door.rotations = ["door-nonce-2"];
  assert.strictEqual((await agentFetch(`${DOOR}/v1/messages`)).status, 200);
  assert.strictEqual((await agentFetch(`${DOOR}/v1/messages`)).status, 200);
  assert.strictEqual(door.challenges, 1);
  assert.strictEqual(door.proofs[door.proofs.length - 1].nonce, "door-nonce-2");
  assert.deepStrictEqual(door.refusals, []);
}

async function test_a_second_challenge_is_not_retried() {
  const { agentFetch, door } = await enrolled();
  door.alwaysChallenge = true;
  assert.strictEqual((await agentFetch(`${DOOR}/v1/messages`)).status, 401);
  assert.strictEqual(door.requests, 2);
  assert.strictEqual(door.challenges, 2);
}

async function test_a_token_request_nonce_challenge_is_retried_once() {
  const vouchryx = new StubVouchryx();
  vouchryx.tokenNonceChallenges = ["vouchryx-nonce-1"];
  const { agentFetch, door } = await enrolled({ vouchryx });
  assert.strictEqual((await agentFetch(`${DOOR}/v1/messages`)).status, 200);
  assert.strictEqual(vouchryx.requests.length, 2);
  assert.strictEqual(vouchryx.requests[0].nonce, null);
  assert.strictEqual(vouchryx.requests[1].nonce, "vouchryx-nonce-1");
  assert.deepStrictEqual(door.refusals, []);

  const stubborn = new StubVouchryx();
  stubborn.alwaysChallengeToken = true;
  const second = await enrolled({ vouchryx: stubborn });
  await assert.rejects(second.agentFetch(`${DOOR}/v1/messages`), AgentTokenError);
  assert.strictEqual(stubborn.requests.length, 2);
}

async function test_the_enrolment_key_is_form_encoded_in_basic() {
  const { agentFetch, vouchryx } = await enrolled();
  assert.strictEqual((await agentFetch(`${DOOR}/v1/messages`)).status, 200);
  assert.deepStrictEqual(vouchryx.basicSeen, [
    `agent%3A%2F%2Facme%2Ftriage:${encodeURIComponent(SECRET)}`,
  ]);
}

async function test_a_workload_token_is_sent_as_the_client_assertion() {
  const vouchryx = new StubVouchryx();
  const door = new StubDoor(vouchryx);
  const pem = await generateKeyPem();
  const values = ["wl-1", "wl-2"];
  const clock = clockFrom(1_000_000);
  const agentFetch = createAgentFetch({
    issuer: ISSUER,
    key: pem,
    workloadToken: () => values.shift(),
    fetch: stubFetch(vouchryx, door),
    now: clock.now,
  });
  assert.strictEqual((await agentFetch(`${DOOR}/v1/messages`)).status, 200);
  clock.ms = 1_000_000 + 240_000;
  assert.strictEqual((await agentFetch(`${DOOR}/v1/messages`)).status, 200);
  assert.deepStrictEqual(vouchryx.assertions, ["wl-1", "wl-2"]);
  assert.strictEqual(vouchryx.requests[0].form.client_assertion_type, JWT_BEARER);
  assert.ok(vouchryx.requests.every((r) => !("authorization" in r.headers)));
}

async function test_the_token_and_the_key_never_reach_a_log_or_an_error() {
  const captured = [];
  const original = {};
  for (const name of ["log", "info", "warn", "error", "debug"]) {
    original[name] = console[name];
    console[name] = (...args) => captured.push(args.map(String).join(" "));
  }
  try {
    const { agentFetch, vouchryx, door, pem } = await enrolled();
    assert.strictEqual((await agentFetch(`${DOOR}/v1/messages`)).status, 200);
    door.refuseAll = true;
    assert.strictEqual((await agentFetch(`${DOOR}/v1/messages`)).status, 401);

    const wrong = new StubVouchryx(); // holds the real secret, so the wrong one is refused
    const clock = clockFrom(1_000_000);
    const badFetch = wire(wrong, new StubDoor(wrong), clock, pem, {
      clientId: AGENT,
      clientSecret: "wrongsecret-xyz",
    });
    let thrown = null;
    try {
      await badFetch(`${DOOR}/v1/messages`);
    } catch (err) {
      thrown = err;
    }
    assert.ok(thrown instanceof AgentTokenError);

    const keyBody = pem.toString("utf8").split("\n")[1].slice(0, 24);
    const text = [captured.join("\n"), String(thrown && thrown.message)].join("\n");
    assert.ok(!text.includes(vouchryx.lastToken));
    assert.ok(!text.includes(SECRET));
    assert.ok(!text.includes("wrongsecret-xyz"));
    assert.ok(!text.includes(keyBody));
  } finally {
    for (const name of Object.keys(original)) console[name] = original[name];
  }
}

async function test_the_key_must_be_an_es256_key() {
  const vouchryx = new StubVouchryx();
  const pem = await generateKeyPem("secp384r1");
  assert.throws(
    () =>
      createAgentFetch({
        issuer: ISSUER,
        key: pem,
        clientId: AGENT,
        clientSecret: SECRET,
        fetch: stubFetch(vouchryx, new StubDoor(vouchryx)),
      }),
    TypeError,
  );
  assert.strictEqual(vouchryx.requests.length, 0);
}

const agentTests = [
  test_fetches_a_token_and_sends_it_with_a_fresh_proof,
  test_refreshes_at_eighty_percent_of_the_lifetime,
  test_each_proof_names_its_request_and_its_token,
  test_a_nonce_challenge_is_retried_once_with_the_nonce,
  test_the_newest_nonce_is_used_next,
  test_a_second_challenge_is_not_retried,
  test_a_token_request_nonce_challenge_is_retried_once,
  test_the_enrolment_key_is_form_encoded_in_basic,
  test_a_workload_token_is_sent_as_the_client_assertion,
  test_the_token_and_the_key_never_reach_a_log_or_an_error,
  test_the_key_must_be_an_es256_key,
];

(async () => {
  let failed = 0;
  for (const test of agentTests) {
    try {
      await test();
      console.log(`ok - ${test.name}`);
    } catch (err) {
      failed += 1;
      console.log(`not ok - ${test.name}: ${err && err.message}`);
    }
  }
  if (failed) {
    process.exitCode = 1;
  } else {
    console.log("ok - tokenfuse js agent helper");
  }
})();
