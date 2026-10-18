"""Tests for tokenfuse.agent, the agent token helper (wave 1 T5).

Each test is bound to a scenario of features/the-sdk-holds-an-agent-token.feature
under the same name, and the JS helper has a test of the same name in
sdk/js/test.js.

The stub vouchryx and the stub door are written from the wire contracts, not
from the helper: vouchryx's token endpoint (internal/api/agents.go, grant
client_credentials, client_secret_basic with RFC 6749 section 2.3.1 encoding,
RFC 7523 client assertions, a DPoP proof required) and the door's proof checks
(RFC 9449 sections 4.2, 8 and 9). Signatures are checked with the cryptography
library's own verifier, not with the helper's signing path.
"""

import asyncio
import base64
import hashlib
import json
import logging
import secrets
import time
import urllib.parse

import httpx
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from tokenfuse.agent import AgentAuth, AgentTokenError

ISSUER = "https://vouchryx.example"
DOOR = "https://door.example"
AGENT = "agent://acme/triage"
SECRET = "s3cr3t+key:/with-chars"
JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _ath(token: str) -> str:
    return _b64url(hashlib.sha256(token.encode("ascii")).digest())


def _pem_key(curve=ec.SECP256R1):
    key = ec.generate_private_key(curve())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return key, pem


def _verify_compact(compact: str):
    """Check an ES256 compact JWS against the public key in its own header."""
    head, body, sig = compact.split(".")
    header = json.loads(_b64url_decode(head))
    payload = json.loads(_b64url_decode(body))
    jwk = header["jwk"]
    public = ec.EllipticCurvePublicNumbers(
        int.from_bytes(_b64url_decode(jwk["x"]), "big"),
        int.from_bytes(_b64url_decode(jwk["y"]), "big"),
        ec.SECP256R1(),
    ).public_key()
    raw = _b64url_decode(sig)
    der = encode_dss_signature(
        int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    )
    public.verify(der, f"{head}.{body}".encode("ascii"), ec.ECDSA(hashes.SHA256()))
    return header, payload


class FakeClock:
    def __init__(self, now: float = 1000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


class StubVouchryx:
    """The token endpoint, as vouchryx serves it for an enrolled agent."""

    def __init__(self, client_secret: str = SECRET):
        self.client_secret = client_secret
        self.issued = set()
        self.requests = []
        self.basic_seen = []
        self.assertions = []
        self.token_nonce_challenges = []
        self.always_challenge_token = False
        self.expected_token_nonce = None
        self.expires_in = 300
        self.last_token = None

    def handle(self, request):
        form = dict(urllib.parse.parse_qsl(request.content.decode("ascii")))
        record = {
            "form": form,
            "headers": {k.lower(): v for k, v in request.headers.items()},
            "nonce": None,
        }
        self.requests.append(record)
        proof = request.headers.get("DPoP", "")
        if not proof:
            return httpx.Response(400, json={"error": "invalid_grant"})
        try:
            _, payload = _verify_compact(proof)
        except (InvalidSignature, ValueError):
            return httpx.Response(400, json={"error": "invalid_grant"})
        record["nonce"] = payload.get("nonce")
        if (
            payload.get("htm") != "POST"
            or payload.get("htu") != f"{ISSUER}/v1/token"
            or "ath" in payload
        ):
            return httpx.Response(400, json={"error": "invalid_grant"})

        challenge = None
        if self.token_nonce_challenges:
            challenge = self.token_nonce_challenges.pop(0)
            self.expected_token_nonce = challenge
        elif self.always_challenge_token:
            challenge = f"v-n{len(self.requests)}"
            self.expected_token_nonce = challenge
        elif (
            self.expected_token_nonce is not None
            and payload.get("nonce") != self.expected_token_nonce
        ):
            challenge = self.expected_token_nonce
        if challenge is not None:
            return httpx.Response(
                400,
                json={"error": "use_dpop_nonce"},
                headers={"DPoP-Nonce": challenge},
            )

        if form.get("grant_type") != "client_credentials":
            return httpx.Response(400, json={"error": "unsupported_grant_type"})
        if "client_assertion" in form:
            assertion = form["client_assertion"]
            self.assertions.append(assertion)
            if form.get("client_assertion_type") != JWT_BEARER or not assertion.startswith("wl-"):
                return httpx.Response(401, json={"error": "invalid_client"})
        else:
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Basic "):
                return httpx.Response(
                    401,
                    json={"error": "invalid_client"},
                    headers={"WWW-Authenticate": "Basic"},
                )
            decoded = base64.b64decode(auth[len("Basic "):]).decode("ascii")
            self.basic_seen.append(decoded)
            client_id, _, secret = decoded.partition(":")
            if (
                urllib.parse.unquote(client_id) != AGENT
                or urllib.parse.unquote(secret) != self.client_secret
            ):
                return httpx.Response(401, json={"error": "invalid_client"})

        token = f"tok-{len(self.issued) + 1}-{secrets.token_hex(8)}"
        self.issued.add(token)
        self.last_token = token
        return httpx.Response(
            200,
            json={"access_token": token, "token_type": "DPoP", "expires_in": self.expires_in},
        )


class StubDoor:
    """A TokenFuse door: checks the DPoP proof of every request, as the delegation crate does."""

    def __init__(self, vouchryx: StubVouchryx):
        self.vouchryx = vouchryx
        self.nonce = None
        self.rotations = []
        self.always_challenge = False
        self.refuse_all = False
        self.proofs = []
        self.refusals = []
        self.requests = 0
        self.challenges = 0
        self.seen_jtis = set()

    def handle(self, request):
        self.requests += 1
        auth = request.headers.get("Authorization", "")
        proof = request.headers.get("DPoP", "")
        if self.refuse_all or not auth.startswith("DPoP ") or not proof:
            return httpx.Response(401, json={"error": "invalid_token"})
        token = auth[len("DPoP "):]
        try:
            header, payload = _verify_compact(proof)
        except (InvalidSignature, ValueError) as exc:
            self.refusals.append(f"signature: {exc!r}")
            return httpx.Response(401, json={"error": "invalid_dpop_proof"})
        self.proofs.append(
            {
                "htm": payload.get("htm"),
                "htu": payload.get("htu"),
                "ath": payload.get("ath"),
                "jti": payload.get("jti"),
                "iat": payload.get("iat"),
                "nonce": payload.get("nonce"),
                "token": token,
            }
        )
        problems = []
        if "d" in header["jwk"]:
            problems.append("a private member in the proof's jwk")
        if payload.get("htm") != request.method:
            problems.append("htm")
        if payload.get("htu") != str(request.url).split("?", 1)[0]:
            problems.append("htu")
        if payload.get("ath") != _ath(token):
            problems.append("ath")
        jti = payload.get("jti", "")
        if len(_b64url_decode(jti)) < 12:
            problems.append("jti shorter than 96 bits")
        if jti in self.seen_jtis:
            problems.append("jti reused")
        self.seen_jtis.add(jti)
        if abs(time.time() - payload.get("iat", 0)) > 60:
            problems.append("iat outside the window")
        if problems:
            self.refusals.append(problems)
            return httpx.Response(401, json={"error": "invalid_dpop_proof"})
        if token not in self.vouchryx.issued:
            return httpx.Response(401, json={"error": "invalid_token"})
        if self.always_challenge or (
            self.nonce is not None and payload.get("nonce") != self.nonce
        ):
            self.challenges += 1
            if self.always_challenge:
                self.nonce = f"door-n{self.challenges}"
            return httpx.Response(
                401,
                json={"error": "use_dpop_nonce"},
                headers={
                    "WWW-Authenticate": 'DPoP error="use_dpop_nonce"',
                    "DPoP-Nonce": self.nonce,
                },
            )
        headers = {}
        if self.rotations:
            self.nonce = self.rotations.pop(0)
            headers["DPoP-Nonce"] = self.nonce
        return httpx.Response(200, json={"ok": True}, headers=headers)


def _wire(vouchryx, door, clock, pem, **auth_kwargs):
    """A door client whose agent token comes from the stub vouchryx."""
    auth = AgentAuth(
        ISSUER,
        pem,
        clock=clock,
        token_client=httpx.Client(transport=httpx.MockTransport(vouchryx.handle)),
        **auth_kwargs,
    )
    client = httpx.Client(auth=auth, transport=httpx.MockTransport(door.handle))
    return client, auth


def _enrolled(vouchryx=None, door_nonce=None):
    _, pem = _pem_key()
    vouchryx = vouchryx or StubVouchryx()
    door = StubDoor(vouchryx)
    if door_nonce is not None:
        door.nonce = door_nonce
    clock = FakeClock()
    client, auth = _wire(
        vouchryx, door, clock, pem, client_id=AGENT, client_secret=SECRET
    )
    return client, vouchryx, door, clock, pem


def test_fetches_a_token_and_sends_it_with_a_fresh_proof():
    client, vouchryx, door, _, _ = _enrolled()
    for _ in range(2):
        assert client.get(f"{DOOR}/v1/messages").status_code == 200
    assert len(vouchryx.requests) == 1
    assert door.refusals == []
    assert len(door.proofs) == 2
    assert door.proofs[0]["jti"] != door.proofs[1]["jti"]
    assert {p["token"] for p in door.proofs} == {vouchryx.last_token}


def test_refreshes_at_eighty_percent_of_the_lifetime():
    client, vouchryx, _, clock, _ = _enrolled()
    client.get(f"{DOOR}/v1/messages")
    clock.now = 1239.0
    client.get(f"{DOOR}/v1/messages")
    assert len(vouchryx.requests) == 1
    clock.now = 1240.0
    client.get(f"{DOOR}/v1/messages")
    assert len(vouchryx.requests) == 2


def test_each_proof_names_its_request_and_its_token():
    client, vouchryx, door, _, _ = _enrolled()
    assert client.get(f"{DOOR}/v1/messages?stream=1&x=2").status_code == 200
    seen = door.proofs[-1]
    assert seen["htm"] == "GET"
    assert seen["htu"] == f"{DOOR}/v1/messages"
    assert seen["ath"] == _ath(vouchryx.last_token)
    assert len(_b64url_decode(seen["jti"])) >= 12
    assert abs(seen["iat"] - time.time()) < 60
    assert door.refusals == []


def test_a_nonce_challenge_is_retried_once_with_the_nonce():
    client, _, door, _, _ = _enrolled(door_nonce="door-nonce-1")
    assert client.get(f"{DOOR}/v1/messages").status_code == 200
    assert door.challenges == 1
    assert len(door.proofs) == 2
    assert door.proofs[0]["nonce"] is None
    assert door.proofs[1]["nonce"] == "door-nonce-1"
    assert door.refusals == []


def test_the_newest_nonce_is_used_next():
    client, _, door, _, _ = _enrolled(door_nonce="door-nonce-1")
    door.rotations = ["door-nonce-2"]
    assert client.get(f"{DOOR}/v1/messages").status_code == 200
    assert client.get(f"{DOOR}/v1/messages").status_code == 200
    assert door.challenges == 1
    assert door.proofs[-1]["nonce"] == "door-nonce-2"
    assert door.refusals == []


def test_a_second_challenge_is_not_retried():
    client, _, door, _, _ = _enrolled()
    door.always_challenge = True
    assert client.get(f"{DOOR}/v1/messages").status_code == 401
    assert door.requests == 2
    assert door.challenges == 2


def test_a_token_request_nonce_challenge_is_retried_once():
    vouchryx = StubVouchryx()
    vouchryx.token_nonce_challenges = ["vouchryx-nonce-1"]
    client, _, door, _, _ = _enrolled(vouchryx=vouchryx)
    assert client.get(f"{DOOR}/v1/messages").status_code == 200
    assert len(vouchryx.requests) == 2
    assert vouchryx.requests[0]["nonce"] is None
    assert vouchryx.requests[1]["nonce"] == "vouchryx-nonce-1"
    assert door.refusals == []

    stubborn = StubVouchryx()
    stubborn.always_challenge_token = True
    client, _, _, _, _ = _enrolled(vouchryx=stubborn)
    with pytest.raises(AgentTokenError):
        client.get(f"{DOOR}/v1/messages")
    assert len(stubborn.requests) == 2


def test_the_enrolment_key_is_form_encoded_in_basic():
    client, vouchryx, _, _, _ = _enrolled()
    assert client.get(f"{DOOR}/v1/messages").status_code == 200
    assert vouchryx.basic_seen == [
        "agent%3A%2F%2Facme%2Ftriage:" + urllib.parse.quote(SECRET, safe="")
    ]


def test_a_workload_token_is_sent_as_the_client_assertion():
    vouchryx = StubVouchryx()
    door = StubDoor(vouchryx)
    _, pem = _pem_key()
    values = iter(["wl-1", "wl-2"])
    clock = FakeClock()
    client, _ = _wire(
        vouchryx, door, clock, pem, workload_token=lambda: next(values)
    )
    assert client.get(f"{DOOR}/v1/messages").status_code == 200
    clock.now = 1240.0
    assert client.get(f"{DOOR}/v1/messages").status_code == 200
    assert vouchryx.assertions == ["wl-1", "wl-2"]
    assert vouchryx.requests[0]["form"]["client_assertion_type"] == JWT_BEARER
    assert all("authorization" not in r["headers"] for r in vouchryx.requests)


def test_the_token_and_the_key_never_reach_a_log_or_an_error(caplog, capsys):
    caplog.set_level(logging.DEBUG)
    client, vouchryx, door, _, pem = _enrolled()
    assert client.get(f"{DOOR}/v1/messages").status_code == 200
    door.refuse_all = True
    assert client.get(f"{DOOR}/v1/messages").status_code == 401

    wrong = StubVouchryx(client_secret="wrongsecret-xyz")
    client2, _ = _wire(
        wrong,
        StubDoor(wrong),
        FakeClock(),
        pem,
        client_id=AGENT,
        client_secret="wrongsecret-xyz",
    )
    with pytest.raises(AgentTokenError) as excinfo:
        client2.get(f"{DOOR}/v1/messages")

    captured = capsys.readouterr()
    text = "\n".join(
        [caplog.text, captured.out, captured.err, str(excinfo.value)]
    )
    assert vouchryx.last_token not in text
    assert SECRET not in text
    assert "wrongsecret-xyz" not in text
    key_body = pem.decode("ascii").splitlines()[1][:24]
    assert key_body not in text


def test_the_key_must_be_an_es256_key():
    vouchryx = StubVouchryx()
    _, pem = _pem_key(ec.SECP384R1)
    with pytest.raises(ValueError):
        AgentAuth(
            ISSUER,
            pem,
            client_id=AGENT,
            client_secret=SECRET,
            token_client=httpx.Client(transport=httpx.MockTransport(vouchryx.handle)),
        )
    assert vouchryx.requests == []


def test_an_async_client_gets_a_token_and_sends_it():
    vouchryx = StubVouchryx()
    door = StubDoor(vouchryx)
    _, pem = _pem_key()

    async def run():
        auth = AgentAuth(
            ISSUER,
            pem,
            client_id=AGENT,
            client_secret=SECRET,
            async_token_client=httpx.AsyncClient(
                transport=httpx.MockTransport(vouchryx.handle)
            ),
        )
        async with httpx.AsyncClient(
            auth=auth, transport=httpx.MockTransport(door.handle)
        ) as client:
            return await client.get(f"{DOOR}/v1/messages")

    assert asyncio.run(run()).status_code == 200
    assert len(vouchryx.requests) == 1
    assert door.refusals == []
