"""A small, deliberately boring HTTP client for the analysis API.

entsec makes one kind of outbound request: a completion call to a
configured API base. That is a much narrower job than a general client, so this
does not try to be one. Everything here exists to make the single request safe
and its failures legible.

The base URL is operator-configurable, which is the reason the SSRF guard is
present at all: a self-hosted gateway is a legitimate deployment, and a base URL
of ``http://169.254.169.254/`` is not. Redirects are refused outright rather
than followed and re-validated -- an API endpoint that redirects is either
misconfigured or hostile, and there is no third case worth supporting.
"""

from __future__ import annotations

import ipaddress
import json
import socket
from typing import Any
from urllib.parse import urlsplit

import httpx

from .validation import ValidationError, safe_text

# The response is a JSON document of bounded size. A body larger than this is a
# malfunction or an attempt to exhaust memory, and reading it to find out costs
# more than refusing it.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
DEFAULT_TIMEOUT = 120.0


class HTTPError(Exception):
    """The request could not be completed."""


def _classify(host: str, *, allow_internal: bool) -> None:
    """Refuse a host that resolves anywhere an API should not live."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise ValidationError(f"cannot resolve {host}: {exc}") from exc

    for info in infos:
        raw = info[4][0]
        try:
            # An IPv6 sockaddr can carry a scope id -- fe80::1%eth0. Recent
            # Pythons parse that form and keep the scope; the split makes the
            # classification independent of which ones do, since the scope says
            # nothing about whether the address is routable.
            address = ipaddress.ip_address(str(raw).split("%", 1)[0])
        except ValueError as exc:
            # Fail closed. Skipping the entry on a parse failure was the wrong
            # half of the choice: an address this cannot parse is one it cannot
            # classify, and if it is the only one the host resolves to, the loop
            # ended with nothing checked and the request went ahead. "We could
            # not tell" must never read as "it is fine".
            raise ValidationError(
                f"{host} resolves to {raw!r}, which is not a parseable address"
            ) from exc

        # IPv4-mapped and 6to4 spellings reach the same address through a
        # different notation. Checking only the textual form would let
        # ::ffff:169.254.169.254 through a filter that blocks the v4 spelling.
        if isinstance(address, ipaddress.IPv6Address):
            if address.ipv4_mapped:
                address = address.ipv4_mapped
            elif address.sixtofour:
                address = address.sixtofour

        if allow_internal:
            continue
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_multicast
            or address.is_unspecified
            # Last, and not redundant with the flags above. 100.64.0.0/10 is
            # carrier-grade NAT -- where a cloud provider's own internal
            # services sit -- and it is neither private nor reserved on every
            # Python version this supports. The named flags catch what they
            # name; this catches everything else that is not globally routable
            # unicast.
            or not address.is_global
        ):
            raise ValidationError(
                f"{host} resolves to {address}, which is not a public address. "
                "Set allow_internal only for a self-hosted gateway you control."
            )


def assert_api_url(url: str, *, allow_internal: bool = False, allow_http: bool = False) -> str:
    """Validate an API base URL before anything is sent to it."""
    text = str(url).strip()
    parts = urlsplit(text)

    if parts.scheme not in {"http", "https"}:
        raise ValidationError(f"unsupported scheme in {text!r}; use https")
    if parts.scheme == "http" and not allow_http:
        raise ValidationError(
            f"{text} uses plain HTTP, which would put the API key on the wire in clear text"
        )
    if parts.username or parts.password:
        raise ValidationError("credentials in a URL are not supported; use the API key header")
    if not parts.hostname:
        raise ValidationError(f"no host in {text!r}")

    _classify(parts.hostname, allow_internal=allow_internal)
    return text


def post_json(
    url: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str],
    timeout: float = DEFAULT_TIMEOUT,
    verify_tls: bool = True,
    allow_internal: bool = False,
    allow_http: bool = False,
) -> dict[str, Any]:
    """POST *payload* and return the decoded response.

    Redirects are not followed. Streaming with an incremental cap rather than
    ``response.json()`` so an oversized body is abandoned mid-transfer instead
    of being buffered in full and then rejected.
    """
    assert_api_url(url, allow_internal=allow_internal, allow_http=allow_http)

    for key, value in headers.items():
        if "\n" in value or "\r" in value:
            raise ValidationError(f"header {key} contains a newline")

    body = json.dumps(payload).encode("utf-8")
    chunks: list[bytes] = []
    total = 0

    try:
        with (
            httpx.Client(timeout=timeout, verify=verify_tls, follow_redirects=False) as client,
            client.stream(
                "POST",
                url,
                content=body,
                headers={**headers, "content-type": "application/json"},
            ) as response,
        ):
            if response.is_redirect:
                raise HTTPError(
                    f"the API endpoint returned a redirect ({response.status_code}). "
                    "Redirects are not followed; check the configured base URL."
                )
            # Streamed with an incremental cap rather than reading the body and
            # then checking its size: an oversized response is abandoned
            # mid-transfer instead of being buffered in full first.
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    raise HTTPError(f"response exceeds {MAX_RESPONSE_BYTES} bytes; abandoned")
                chunks.append(chunk)
            status = response.status_code
    except httpx.HTTPError as exc:
        # Truncated to scheme and host: a full URL in an error string reaches
        # logs and reports, and query strings carry tokens more often than
        # anyone intends.
        parts = urlsplit(url)
        raise HTTPError(
            f"request to {parts.scheme}://{parts.netloc} failed: {type(exc).__name__}"
        ) from exc

    raw = b"".join(chunks)
    if status >= 400:
        detail = safe_text(raw.decode("utf-8", "replace"), limit=300)
        raise HTTPError(f"API returned {status}: {detail}")

    try:
        decoded = json.loads(raw)
    except ValueError as exc:
        raise HTTPError(f"API returned a body that is not JSON: {exc}") from exc
    if not isinstance(decoded, dict):
        raise HTTPError("API returned JSON that is not an object")
    return decoded
