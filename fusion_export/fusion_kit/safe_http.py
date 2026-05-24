"""SSRF guard for outbound HTTP fetches in the L2 fusion sidecar.

Mirrors the Go enricher's safeDialContext / isPublicIP at
internal/phishing/enricher/http.go. Rejects loopback, link-local
(incl. 169.254.169.254 cloud metadata), private (RFC1918/RFC4193),
multicast, reserved, and unspecified addresses.

Two surfaces:

* requests.Session — SSRFGuardedAdapter validates the target host on
  every `send()`. requests.Session.resolve_redirects re-enters the
  adapter on each redirect hop, so a public-to-internal redirect chain
  is rejected at the boundary.

* aiohttp.ClientSession — SSRFGuardedConnector overrides
  _resolve_host so DNS rebinding between resolve and connect is not
  exploitable: only the IPs the resolver returned (and which we filtered
  here) are used to dial.

The Python sidecar is invoked by the Go service on the /score
fallback path (Go enricher init failure or per-request enricher
error). The Go side is already guarded — this closes the same hole
on the Python side.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import List, Optional, Sequence
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

try:
    import aiohttp
    from aiohttp.abc import ResolveResult
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    aiohttp = None  # type: ignore[assignment]
    ResolveResult = dict  # type: ignore[misc,assignment]


_BLOCKED_IP_MSG = "blocked: non-public IP address"
_BLOCKED_SCHEME_MSG = "blocked: non-http(s) scheme"
_BLOCKED_NOHOST_MSG = "blocked: URL has no host"


class BlockedAddressError(requests.exceptions.ConnectionError):
    """Outbound HTTP target resolved to a non-public IP, or used a non-http(s) scheme.

    Subclasses requests.exceptions.ConnectionError (in turn an OSError), so
    existing `except ConnectionError` / `except Exception` blocks in
    enrich.py catch it without changes.
    """


def is_public_ip(ip) -> bool:
    """Return True iff `ip` is safe to dial server-side.

    Rejects loopback (127/8, ::1), link-local (169.254/16 incl. AWS/GCE
    metadata at 169.254.169.254, fe80::/10), private (RFC1918, RFC4193),
    multicast, reserved blocks (incl. 0.0.0.0/8, 100.64/10 CGNAT,
    240/4), and the all-zero unspecified address. Mirrors the Go
    `isPublicIP` semantics from internal/phishing/enricher/http.go.
    """
    return not (
        ip.is_unspecified
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_private
        or ip.is_reserved
    )


def _check_host_public(host: str) -> None:
    """Raise BlockedAddressError unless `host` resolves to *only* public IPs.

    A multi-record A/AAAA response containing any non-public address is
    rejected — DNS pinning is not in scope here; the strict policy is
    that any infrastructure record pointing at internal space is
    treated as adversarial.
    """
    try:
        ip = ipaddress.ip_address(host)
        if not is_public_ip(ip):
            raise BlockedAddressError(_BLOCKED_IP_MSG)
        return
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise BlockedAddressError(f"blocked: DNS lookup failed for {host}: {exc}") from exc

    any_public = False
    for _fam, _, _, _, sockaddr in infos:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        if not is_public_ip(ip):
            raise BlockedAddressError(_BLOCKED_IP_MSG)
        any_public = True
    if not any_public:
        raise BlockedAddressError(_BLOCKED_IP_MSG)


def validate_url(url: str) -> None:
    """Pre-flight URL check: reject non-http(s) schemes and non-public hosts."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise BlockedAddressError(_BLOCKED_SCHEME_MSG)
    if not parsed.hostname:
        raise BlockedAddressError(_BLOCKED_NOHOST_MSG)
    _check_host_public(parsed.hostname)


def safe_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, *, source_address=None):
    """SSRF-guarded drop-in for socket.create_connection.

    Resolves `host`, filters out non-public addresses, then dials a literal
    public IP (so DNS rebinding between resolve and connect cannot win). The
    caller is expected to pass `server_hostname=<original-host>` when
    wrapping the socket for TLS so SNI / cert validation still uses the
    intended name.

    Raises BlockedAddressError if no public IP resolves.
    """
    host, port = address
    # Literal IP fast path.
    try:
        ip_obj = ipaddress.ip_address(host)
        if not is_public_ip(ip_obj):
            raise BlockedAddressError(_BLOCKED_IP_MSG)
        return socket.create_connection((host, port), timeout=timeout, source_address=source_address)
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise BlockedAddressError(f"blocked: DNS lookup failed for {host}: {exc}") from exc

    last_err: Optional[BaseException] = None
    for family, sock_type, proto, _canon, sockaddr in infos:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        if not is_public_ip(ip):
            raise BlockedAddressError(_BLOCKED_IP_MSG)
        sock = socket.socket(family, sock_type, proto)
        try:
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(timeout)
            if source_address is not None:
                sock.bind(source_address)
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            last_err = exc
            sock.close()
    if last_err is not None:
        raise last_err
    raise BlockedAddressError(_BLOCKED_IP_MSG)


class SSRFGuardedAdapter(HTTPAdapter):
    """HTTPAdapter that validates the request URL against the public-IP filter.

    Invoked once per outbound request *and* once per redirect hop
    (Session.resolve_redirects re-enters through Session.get_adapter), so a
    redirect from a public host to an internal IP is rejected at the
    second-hop boundary.
    """

    def send(self, request, **kwargs):  # type: ignore[override]
        validate_url(request.url or "")
        return super().send(request, **kwargs)


def mount_ssrf_guard(
    session: requests.Session,
    *,
    max_retries=0,
    pool_connections: int = 10,
    pool_maxsize: int = 10,
    pool_block: bool = False,
) -> requests.Session:
    """Replace the http:// and https:// adapters with SSRF-guarded ones.

    Accepts the same pool/retry tuning kwargs as HTTPAdapter so callers can
    preserve their existing pool config (notably enrich.py:get_http_session).
    """
    adapter = SSRFGuardedAdapter(
        max_retries=max_retries,
        pool_connections=pool_connections,
        pool_maxsize=pool_maxsize,
        pool_block=pool_block,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def safe_session(**adapter_kwargs) -> requests.Session:
    """Create a new requests.Session with SSRF guard mounted."""
    return mount_ssrf_guard(requests.Session(), **adapter_kwargs)


if AIOHTTP_AVAILABLE:

    class SSRFGuardedConnector(aiohttp.TCPConnector):  # type: ignore[misc]
        """TCPConnector that rejects resolved hosts pointing at internal IPs.

        Follows the aiohttp SSRF cookbook pattern: override _resolve_host so
        the upstream resolution (default or aiodns) still runs, but every
        record is filtered through `is_public_ip` before connect. Because
        aiohttp connects to the addresses returned here, DNS rebinding
        between resolve and connect cannot win.
        """

        async def _resolve_host(  # type: ignore[override]
            self,
            host: str,
            port: int,
            traces: Optional[Sequence] = None,
        ) -> List[ResolveResult]:  # type: ignore[valid-type]
            res = await super()._resolve_host(host, port, traces)
            for r in res:
                try:
                    ip = ipaddress.ip_address(r["host"])
                except ValueError:
                    continue
                if not is_public_ip(ip):
                    raise BlockedAddressError(_BLOCKED_IP_MSG)
            return res
else:

    class SSRFGuardedConnector:  # type: ignore[no-redef]
        def __init__(self, *_, **__):
            raise RuntimeError("aiohttp is not installed; SSRFGuardedConnector unavailable")
