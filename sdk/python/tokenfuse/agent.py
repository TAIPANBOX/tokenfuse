"""Agent token helper: an httpx auth that holds an agent's ES256 key.

The helper asks vouchryx for an agent token (client_credentials, with a DPoP proof),
caches it, asks again at 80 percent of its life, and sends each request to a
TokenFuse door as ``Authorization: DPoP <token>`` with a proof made for that request.

Nonces (RFC 9449 sections 8 and 9): a door may answer 401 with
``WWW-Authenticate: DPoP error="use_dpop_nonce"`` and a DPoP-Nonce header, and
vouchryx's token endpoint may answer 400 ``use_dpop_nonce``. Each such challenge is
answered by one retry that carries the nonce. The newest DPoP-Nonce a server sent
is used for every later request to it. A second challenge is returned to the
caller, never retried.

The key stays inside this object and is never logged or put in an error. The
helper needs httpx, and cryptography for the ECDSA signature.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import secrets
import threading
import time
import urllib.parse
from typing import Any, Callable, Dict, NamedTuple, Optional, Tuple

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

__all__ = ["AgentAuth", "AgentTokenError"]

REFRESH_AT = 0.8  # a token is asked for again once this share of its life has passed
JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
DPOP_NONCE = "use_dpop_nonce"

_LOG = logging.getLogger("tokenfuse.agent")


class AgentTokenError(Exception):
    """The token request or a door's answer could not be completed.

    The message never carries a token, a key or an enrolment secret.
    """


class _Token(NamedTuple):
    value: str
    obtained: float
    lifetime: float


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _ath(token: str) -> str:
    """RFC 9449 section 4.2: base64url of the SHA-256 of the access token."""
    return _b64url(hashlib.sha256(token.encode("ascii")).digest())


def _htu(url: Any) -> str:
    """The request URL without its query and fragment (RFC 9449 section 4.2)."""
    return str(url).split("#", 1)[0].split("?", 1)[0]


def _origin(url: Any) -> Tuple[str, Optional[str], Optional[int]]:
    parsed = httpx.URL(str(url))
    return (parsed.scheme, parsed.host, parsed.port)


def _load_key(key: Any) -> ec.EllipticCurvePrivateKey:
    if isinstance(key, str):
        key = key.encode("ascii")
    if isinstance(key, bytes):
        try:
            key = serialization.load_pem_private_key(key, password=None)
        except (ValueError, TypeError):
            raise ValueError("the agent key is not a PEM private key") from None
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("the agent key must be an ES256 (P-256) private key")
    return key


def _public_jwk(key: ec.EllipticCurvePrivateKey) -> Dict[str, str]:
    numbers = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(numbers.x.to_bytes(32, "big")),
        "y": _b64url(numbers.y.to_bytes(32, "big")),
    }


def _jws(key: ec.EllipticCurvePrivateKey, header: Dict[str, Any], payload: Dict[str, Any]) -> str:
    head = _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    body = _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{head}.{body}".encode("ascii")
    r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{head}.{body}.{_b64url(signature)}"


def _proof(
    key: ec.EllipticCurvePrivateKey,
    method: str,
    url: Any,
    token: Optional[str] = None,
    nonce: Optional[str] = None,
) -> str:
    """A DPoP proof for one request: fresh jti and iat, the token's hash when there is one."""
    payload: Dict[str, Any] = {
        "jti": secrets.token_urlsafe(16),  # 128 random bits; RFC 9449 section 4.2 asks for 96
        "htm": method.upper(),
        "htu": _htu(url),
        "iat": int(time.time()),
    }
    if token is not None:
        payload["ath"] = _ath(token)
    if nonce is not None:
        payload["nonce"] = nonce
    return _jws(key, {"typ": "dpop+jwt", "alg": "ES256", "jwk": _public_jwk(key)}, payload)


def _refusal_code(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return ""
    code = body.get("error") if isinstance(body, dict) else None
    return code if isinstance(code, str) else ""


def _is_token_challenge(response: httpx.Response) -> bool:
    return (
        response.status_code == 400
        and _refusal_code(response) == DPOP_NONCE
        and bool(response.headers.get("DPoP-Nonce"))
    )


def _is_door_challenge(response: httpx.Response) -> bool:
    challenge = response.headers.get("WWW-Authenticate", "")
    return (
        response.status_code == 401
        and "DPoP" in challenge
        and 'error="use_dpop_nonce"' in challenge
        and bool(response.headers.get("DPoP-Nonce"))
    )


def _token_from(response: httpx.Response, obtained: float) -> _Token:
    if response.status_code != 200:
        code = _refusal_code(response)
        suffix = f" ({code})" if code else ""
        raise AgentTokenError(
            f"vouchryx refused the token request: HTTP {response.status_code}{suffix}"
        )
    try:
        body = response.json()
    except ValueError:
        body = None
    if not isinstance(body, dict):
        raise AgentTokenError("vouchryx's token answer is not a JSON object")
    value = body.get("access_token")
    lifetime = body.get("expires_in")
    if (
        not isinstance(value, str)
        or not value
        or isinstance(lifetime, bool)
        or not isinstance(lifetime, (int, float))
        or lifetime <= 0
    ):
        raise AgentTokenError("vouchryx's token answer carries no usable access_token and expires_in")
    _LOG.debug("agent token obtained, valid for %s seconds", lifetime)
    return _Token(value, obtained, float(lifetime))


class AgentAuth(httpx.Auth):
    """An httpx auth that sends each request with an agent token and a fresh proof.

    Either the enrolment key (``client_id`` with ``client_secret``) or a workload
    token (``workload_token``, a callable that returns the projected token now) asks
    vouchryx for the token. ``audience`` is sent as ``resource``. ``clock`` measures
    the token's age and must not go backwards; the default is ``time.monotonic``.
    ``token_client`` and ``async_token_client`` are the clients the token requests
    use, and are created when not given.
    """

    requires_request_body = False
    requires_response_body = False

    def __init__(
        self,
        issuer: str,
        key: Any,
        *,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        workload_token: Optional[Callable[[], str]] = None,
        audience: Optional[str] = None,
        clock: Callable[[], float] = time.monotonic,
        token_client: Optional[httpx.Client] = None,
        async_token_client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        if (client_id is None) == (workload_token is None):
            raise ValueError(
                "give either client_id with client_secret, or workload_token; not both, and not neither"
            )
        if client_id is not None and client_secret is None:
            raise ValueError("client_id needs client_secret, the enrolment key")
        if workload_token is not None and not callable(workload_token):
            raise ValueError("workload_token must be a callable that returns the projected token")
        # Refuse a bad key before any client is built or any request is made.
        self._key = _load_key(key)
        self._issuer = str(issuer).rstrip("/")
        self._token_url = f"{self._issuer}/v1/token"
        self._client_id = client_id
        self._client_secret = client_secret
        self._workload_token = workload_token
        self._audience = audience
        self._clock = clock
        self._owns_token_client = token_client is None
        self._token_client = token_client if token_client is not None else httpx.Client()
        self._async_token_client = async_token_client
        self._token: Optional[_Token] = None
        self._lock = threading.Lock()
        self._async_lock: Optional[asyncio.Lock] = None
        self._nonces: Dict[Tuple[str, Optional[str], Optional[int]], str] = {}
        self._nonce_lock = threading.Lock()

    def close(self) -> None:
        """Close the sync token client when this object made it.

        An async token client is closed by whoever passed it in, or with aclose()
        on the one this object made.
        """
        if self._owns_token_client:
            self._token_client.close()

    # --- nonces: the newest DPoP-Nonce a server sent is the one used next (RFC 9449 8.2)

    def _nonce_for(self, url: Any) -> Optional[str]:
        with self._nonce_lock:
            return self._nonces.get(_origin(url))

    def _remember(self, url: Any, response: httpx.Response) -> None:
        nonce = response.headers.get("DPoP-Nonce")
        if nonce:
            with self._nonce_lock:
                self._nonces[_origin(url)] = nonce

    # --- the agent token

    def _stale(self, token: _Token) -> bool:
        # age >= 80 percent of the lifetime, written without a float ratio
        return 5 * (self._clock() - token.obtained) >= 4 * token.lifetime

    def _token_form(self) -> Tuple[Dict[str, str], Dict[str, str]]:
        form = {"grant_type": "client_credentials"}
        if self._audience is not None:
            form["resource"] = self._audience
        if self._client_id is not None:
            # RFC 6749 2.3.1: the id and the secret are form-encoded before the Basic
            # encoding, because an agent id is a URI and its colon would split the pair.
            raw = f"{urllib.parse.quote(self._client_id, safe='')}:{urllib.parse.quote(str(self._client_secret), safe='')}"
            basic = base64.b64encode(raw.encode("ascii")).decode("ascii")
            return form, {"Authorization": f"Basic {basic}"}
        form["client_assertion_type"] = JWT_BEARER
        form["client_assertion"] = self._workload_token()  # read at the time of the request
        return form, {}

    def _token_headers(self, auth: Dict[str, str]) -> Dict[str, str]:
        headers = dict(auth)
        headers["DPoP"] = _proof(
            self._key, "POST", self._token_url, nonce=self._nonce_for(self._token_url)
        )
        return headers

    def _fetch_token(self) -> _Token:
        form, auth = self._token_form()
        response = None
        for attempt in range(2):
            response = self._token_client.post(
                self._token_url, data=form, headers=self._token_headers(auth)
            )
            self._remember(self._token_url, response)
            if attempt == 0 and _is_token_challenge(response):
                continue
            break
        assert response is not None
        return _token_from(response, self._clock())

    def _access_token(self) -> str:
        with self._lock:
            if self._token is None or self._stale(self._token):
                self._token = self._fetch_token()
            return self._token.value

    async def _fetch_token_async(self) -> _Token:
        if self._async_token_client is None:
            self._async_token_client = httpx.AsyncClient()
        client = self._async_token_client
        form, auth = self._token_form()
        response = None
        for attempt in range(2):
            response = await client.post(
                self._token_url, data=form, headers=self._token_headers(auth)
            )
            self._remember(self._token_url, response)
            if attempt == 0 and _is_token_challenge(response):
                continue
            break
        assert response is not None
        return _token_from(response, self._clock())

    async def _access_token_async(self) -> str:
        if self._async_lock is None:
            self._async_lock = asyncio.Lock()
        async with self._async_lock:
            if self._token is None or self._stale(self._token):
                self._token = await self._fetch_token_async()
            return self._token.value

    # --- the door: every request carries its own proof, and a challenge is answered once

    def _sign(self, request: httpx.Request, token: str) -> None:
        request.headers["Authorization"] = f"DPoP {token}"
        request.headers["DPoP"] = _proof(
            self._key,
            request.method,
            request.url,
            token=token,
            nonce=self._nonce_for(request.url),
        )

    def sync_auth_flow(self, request: httpx.Request):
        token = self._access_token()
        self._sign(request, token)
        response = yield request
        self._remember(request.url, response)
        if _is_door_challenge(response):
            self._sign(request, token)
            response = yield request
            self._remember(request.url, response)

    async def async_auth_flow(self, request: httpx.Request):
        token = await self._access_token_async()
        self._sign(request, token)
        response = yield request
        self._remember(request.url, response)
        if _is_door_challenge(response):
            self._sign(request, token)
            response = yield request
            self._remember(request.url, response)
