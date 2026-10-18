"use strict";

/**
 * Agent token helper: a fetch wrapper that holds an agent's ES256 key.
 *
 * The wrapper asks vouchryx for an agent token (client_credentials, with a DPoP
 * proof), caches it, asks again at 80 percent of its life, and sends each request
 * to a TokenFuse door as `Authorization: DPoP <token>` with a proof made for that
 * request. Nonces (RFC 9449 sections 8 and 9) are answered once per request: a door
 * answers 401 with `WWW-Authenticate: DPoP error="use_dpop_nonce"` and a DPoP-Nonce
 * header, and vouchryx answers 400 `use_dpop_nonce`. The newest DPoP-Nonce a server
 * sent is used for every later request to it, and a second challenge is returned to
 * the caller, never retried.
 *
 * The key stays inside this module and is never logged or put in an error. It uses
 * node:crypto only, so the package keeps no runtime dependency. The wrapper needs
 * `fetch`: Node 18 or later, or `options.fetch`.
 */

const crypto = require("node:crypto");

const REFRESH_AT = 0.8; // a token is asked for again once this share of its life has passed
const JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const DPOP_NONCE = "use_dpop_nonce";

class AgentTokenError extends Error {}

function b64url(data) {
  return Buffer.from(data).toString("base64url");
}

function athOf(token) {
  return crypto.createHash("sha256").update(token, "ascii").digest("base64url");
}

function htuOf(url) {
  const target = new URL(String(url));
  target.search = "";
  target.hash = "";
  return target.toString();
}

function loadKey(key) {
  let loaded;
  if (key instanceof crypto.KeyObject) {
    loaded = key;
  } else {
    try {
      loaded = crypto.createPrivateKey(key);
    } catch {
      throw new TypeError("the agent key is not a PEM private key");
    }
  }
  const details = loaded.asymmetricKeyDetails || {};
  if (loaded.type !== "private" || loaded.asymmetricKeyType !== "ec" || details.namedCurve !== "prime256v1") {
    throw new TypeError("the agent key must be an ES256 (P-256) private key");
  }
  return loaded;
}

function publicJwk(key) {
  const { kty, crv, x, y } = crypto.createPublicKey(key).export({ format: "jwk" });
  return { kty, crv, x, y };
}

function jws(key, header, payload) {
  const head = b64url(JSON.stringify(header));
  const body = b64url(JSON.stringify(payload));
  const signature = crypto.sign("sha256", Buffer.from(`${head}.${body}`, "ascii"), {
    key,
    dsaEncoding: "ieee-p1363", // the raw r || s that a JWS carries, not DER
  });
  return `${head}.${body}.${b64url(signature)}`;
}

// A DPoP proof for one request: a fresh jti and iat, the token's hash when there is one.
function proof(key, method, url, token, nonce) {
  const payload = {
    jti: crypto.randomBytes(16).toString("base64url"), // 128 random bits; RFC 9449 asks for 96
    htm: method.toUpperCase(),
    htu: htuOf(url),
    iat: Math.floor(Date.now() / 1000),
  };
  if (token !== undefined) payload.ath = athOf(token);
  if (nonce) payload.nonce = nonce;
  return jws(key, { typ: "dpop+jwt", alg: "ES256", jwk: publicJwk(key) }, payload);
}

function headerEntries(headers) {
  if (!headers) return [];
  if (Array.isArray(headers)) return headers;
  if (typeof headers.forEach === "function") {
    const out = [];
    headers.forEach((value, name) => out.push([name, value]));
    return out;
  }
  return Object.entries(headers);
}

// Copy of the caller's headers with names in lower case, so one name is one key.
function headerMap(headers) {
  const out = {};
  for (const [name, value] of headerEntries(headers)) out[String(name).toLowerCase()] = String(value);
  return out;
}

function isDoorChallenge(res) {
  const challenge = res.headers.get("WWW-Authenticate") || "";
  return (
    res.status === 401 &&
    challenge.includes("DPoP") &&
    challenge.includes('error="use_dpop_nonce"') &&
    Boolean(res.headers.get("DPoP-Nonce"))
  );
}

async function readAnswer(res) {
  const text = await res.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch {
    body = null;
  }
  const code = body && typeof body === "object" && typeof body.error === "string" ? body.error : "";
  return { body, code };
}

function tokenFrom(res, answer, obtained) {
  if (res.status !== 200) {
    const suffix = answer.code ? ` (${answer.code})` : "";
    throw new AgentTokenError(`vouchryx refused the token request: HTTP ${res.status}${suffix}`);
  }
  const { body } = answer;
  if (
    !body ||
    typeof body !== "object" ||
    typeof body.access_token !== "string" ||
    body.access_token === "" ||
    typeof body.expires_in !== "number" ||
    !(body.expires_in > 0)
  ) {
    throw new AgentTokenError("vouchryx's token answer carries no usable access_token and expires_in");
  }
  return { value: body.access_token, obtained, lifetime: body.expires_in * 1000 };
}

/**
 * Build a fetch-compatible function for one agent.
 *
 * Give either `clientId` with `clientSecret` (the enrolment key), or `workloadToken`,
 * a function that returns the projected token at the time it is called. `audience`
 * is sent as `resource`. `now` returns milliseconds and measures the token's age.
 * The key is checked before any request is made: a key that is not an ES256 private
 * key throws a TypeError here.
 *
 * @returns {(input: string | URL, init?: RequestInit) => Promise<Response>}
 */
function createAgentFetch(options = {}) {
  const {
    issuer,
    key,
    clientId,
    clientSecret,
    workloadToken,
    audience,
    fetch: fetchImpl = globalThis.fetch,
    now = Date.now,
  } = options;
  if ((clientId === undefined) === (workloadToken === undefined)) {
    throw new TypeError("give either clientId with clientSecret, or workloadToken; not both, and not neither");
  }
  if (clientId !== undefined && clientSecret === undefined) {
    throw new TypeError("clientId needs clientSecret, the enrolment key");
  }
  if (workloadToken !== undefined && typeof workloadToken !== "function") {
    throw new TypeError("workloadToken must be a function that returns the projected token");
  }
  if (typeof issuer !== "string" || issuer === "") throw new TypeError("issuer is required");
  if (typeof fetchImpl !== "function") {
    throw new TypeError("no fetch is available: pass options.fetch, or run on Node 18 or later");
  }
  const privateKey = loadKey(key); // refused before any request is made
  const tokenUrl = `${issuer.replace(/\/+$/, "")}/v1/token`;

  const nonces = new Map(); // origin -> the newest DPoP-Nonce that server sent
  const originOf = (url) => new URL(String(url)).origin;
  const remember = (url, res) => {
    const nonce = res.headers.get("DPoP-Nonce");
    if (nonce) nonces.set(originOf(url), nonce);
  };
  const nonceFor = (url) => nonces.get(originOf(url));

  let token = null; // { value, obtained, lifetime }, lifetime in milliseconds
  let pending = null;
  const stale = (current) => 5 * (now() - current.obtained) >= 4 * current.lifetime;

  async function fetchToken() {
    const form = new URLSearchParams({ grant_type: "client_credentials" });
    if (audience !== undefined) form.set("resource", audience);
    let basic = null;
    if (clientId !== undefined) {
      // RFC 6749 2.3.1: the id and the secret are form-encoded before the Basic encoding.
      const pair = `${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`;
      basic = `Basic ${Buffer.from(pair, "utf8").toString("base64")}`;
    } else {
      form.set("client_assertion_type", JWT_BEARER);
      form.set("client_assertion", String(workloadToken()));
    }
    for (let attempt = 0; ; attempt += 1) {
      const headers = basic ? { authorization: basic } : {};
      headers.dpop = proof(privateKey, "POST", tokenUrl, undefined, nonceFor(tokenUrl));
      const res = await fetchImpl(tokenUrl, { method: "POST", headers, body: form.toString() });
      remember(tokenUrl, res);
      const answer = await readAnswer(res);
      const challenged =
        res.status === 400 && answer.code === DPOP_NONCE && Boolean(res.headers.get("DPoP-Nonce"));
      if (challenged && attempt === 0) continue; // one retry, carrying the nonce
      return tokenFrom(res, answer, now());
    }
  }

  async function accessToken() {
    if (token !== null && !stale(token)) return token.value;
    if (pending === null) {
      pending = fetchToken().then(
        (fresh) => {
          token = fresh;
          pending = null;
          return fresh;
        },
        (err) => {
          pending = null;
          throw err;
        },
      );
    }
    return (await pending).value;
  }

  async function sendToDoor(target, method, init, value) {
    const headers = headerMap(init.headers);
    headers.authorization = `DPoP ${value}`;
    headers.dpop = proof(privateKey, method, target, value, nonceFor(target));
    return fetchImpl(target, { ...init, method, headers });
  }

  return async function agentFetch(input, init = {}) {
    const target = String(input);
    const method = (init.method || "GET").toUpperCase();
    const value = await accessToken();
    let res = await sendToDoor(target, method, init, value);
    remember(target, res);
    if (isDoorChallenge(res)) {
      res = await sendToDoor(target, method, init, value); // one retry, carrying the nonce
      remember(target, res);
    }
    return res;
  };
}

module.exports = { AgentTokenError, createAgentFetch };
