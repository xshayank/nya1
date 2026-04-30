"""
HTTPForwarder — listens on localhost:<listen_port>, reads incoming plain HTTP
requests, and relays them to the configured target via Google Apps Script
(domain-fronted through www.google.com).
"""

import asyncio
import base64
import gzip
import json
import logging
import ssl
from urllib.parse import urlparse, urlunparse

log = logging.getLogger("Forwarder")

# Well-known Google anycast IPs (domain fronting candidates)
GOOGLE_FALLBACK_IPS = [
    "216.239.38.120",
    "216.239.36.120",
    "216.239.32.120",
    "216.239.34.120",
    "142.250.185.78",
    "142.250.80.46",
    "172.217.16.46",
    "74.125.24.100",
    "64.233.160.100",
]

REASON_PHRASES = {
    200: "OK", 201: "Created", 204: "No Content",
    301: "Moved Permanently", 302: "Found", 303: "See Other",
    304: "Not Modified", 307: "Temporary Redirect", 308: "Permanent Redirect",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
    404: "Not Found", 405: "Method Not Allowed", 429: "Too Many Requests",
    500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
}


class HTTPForwarder:
    def __init__(self, config):
        self._config = config
        self._listen_host = config.get("listen_host", "127.0.0.1")
        self._listen_port = config.get("listen_port", 1080)
        self._target_url  = config["target_url"]   # e.g. "http://test.com:80"
        self._auth_key    = config["auth_key"]
        self._script_ids  = config.get("script_ids") or config.get("script_id")
        if isinstance(self._script_ids, str):
            self._script_ids = [self._script_ids]
        self._front_domain  = config.get("front_domain", "www.google.com")
        self._google_ip     = config.get("google_ip", "")
        self._relay_timeout = config.get("relay_timeout", 25)
        self._script_index  = 0
        self._server = None

    async def start(self):
        self._server = await asyncio.start_server(
            self._handle_connection,
            self._listen_host,
            self._listen_port,
        )
        addr = self._server.sockets[0].getsockname()
        log.info("Listening on %s:%s → %s (via GAS)", addr[0], addr[1], self._target_url)
        async with self._server:
            await self._server.serve_forever()

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_connection(self, reader, writer):
        peer = writer.get_extra_info("peername")
        log.debug("New connection from %s", peer)
        # Idle timeout for waiting for the next request is shorter than the relay timeout.
        idle_timeout = min(10, self._relay_timeout)
        try:
            while True:
                # Read and parse the HTTP request (headers first, then body by Content-Length).
                try:
                    method, path, headers_dict, body = await asyncio.wait_for(
                        _read_http_request(reader),
                        timeout=idle_timeout,
                    )
                except asyncio.TimeoutError:
                    log.debug("Idle timeout on connection from %s", peer)
                    break
                except EOFError:
                    break

                # Build target URL: use target base + request path (preserve query string).
                # A dummy scheme+netloc is required by urlparse to correctly split path and query.
                parsed_target = urlparse(self._target_url)
                req_parsed = urlparse(path if path.startswith("http") else f"http://x{path}")
                full_url = urlunparse((
                    parsed_target.scheme,
                    parsed_target.netloc,
                    req_parsed.path,
                    "",
                    req_parsed.query,
                    "",
                ))

                log.info("%s %s", method, full_url)

                # Relay through GAS
                resp = await self._relay_via_gas(method, full_url, headers_dict, body)

                # Write HTTP response back to client
                writer.write(resp)
                await writer.drain()

                # Check if the client requested connection close
                conn_header = headers_dict.get("Connection", "").lower()
                if conn_header == "close":
                    break

        except asyncio.TimeoutError:
            log.warning("Timeout on connection from %s", peer)
        except Exception as e:
            log.error("Error handling connection from %s: %s", peer, e)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    def _next_script_id(self) -> str:
        """Round-robin over available script IDs."""
        sid = self._script_ids[self._script_index % len(self._script_ids)]
        self._script_index += 1
        return sid

    async def _relay_via_gas(self, method, url, headers, body):
        """Send request to GAS and return raw HTTP response bytes."""
        script_id = self._next_script_id()

        payload = {
            "k": self._auth_key,
            "m": method,
            "u": url,
            "h": headers,
            "ct": headers.get("Content-Type", ""),
        }
        if body:
            payload["b"] = base64.b64encode(body).decode()

        post_body = json.dumps(payload).encode()

        try:
            resp_raw = await self._do_gas_request(script_id, post_body)
            return _build_http_response(resp_raw)

        except Exception as e:
            log.error("GAS relay error: %s", e)
            return b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"

    async def _do_gas_request(self, script_id, post_body):
        """POST to GAS /exec, follow the 302 redirect with GET. Tries multiple IPs on failure."""
        ssl_ctx = ssl.create_default_context()
        exec_path = f"/macros/s/{script_id}/exec"

        # Build ordered list of IPs to try
        ips_to_try = []
        if self._google_ip:
            ips_to_try.append(self._google_ip)
        for ip in GOOGLE_FALLBACK_IPS:
            if ip not in ips_to_try:
                ips_to_try.append(ip)

        last_exc = None
        connect_host = None

        # --- Step 1: POST to /exec, find a working IP ---
        resp_raw = None
        for ip in ips_to_try:
            try:
                resp_raw = await self._raw_https_request(
                    ip, ssl_ctx, exec_path,
                    method="POST",
                    host_header="script.google.com",
                    body=post_body,
                )
                connect_host = ip
                break
            except (OSError, asyncio.TimeoutError) as e:
                log.debug("IP %s failed for POST /exec: %s", ip, e)
                last_exc = e
                continue

        if resp_raw is None:
            raise last_exc or RuntimeError(f"Failed to connect to GAS after trying {len(ips_to_try)} IP(s)")

        # --- Step 2: Follow redirect if 301/302/303 ---
        status, location = _parse_redirect(resp_raw)
        if status in (301, 302, 303) and location:
            log.debug("GAS redirect %d → %s", status, location)
            parsed_loc = urlparse(location)
            redirect_host = parsed_loc.hostname or "script.googleusercontent.com"
            redirect_path = parsed_loc.path
            if parsed_loc.query:
                redirect_path += "?" + parsed_loc.query

            # Follow redirect: GET, no body, correct Host header
            # Try the same IP that worked for step 1 first
            redirect_ips = [connect_host] + [ip for ip in ips_to_try if ip != connect_host]
            for ip in redirect_ips:
                try:
                    resp_raw = await self._raw_https_request(
                        ip, ssl_ctx, redirect_path,
                        method="GET",
                        host_header=redirect_host,
                        body=None,
                    )
                    break
                except (OSError, asyncio.TimeoutError) as e:
                    log.debug("IP %s failed for GET redirect: %s", ip, e)
                    last_exc = e
                    continue

        elif status in (307, 308) and location:
            # 307/308: re-POST to redirect location
            parsed_loc = urlparse(location)
            redirect_host = parsed_loc.hostname or "script.google.com"
            redirect_path = parsed_loc.path
            if parsed_loc.query:
                redirect_path += "?" + parsed_loc.query
            for ip in [connect_host] + [ip for ip in ips_to_try if ip != connect_host]:
                try:
                    resp_raw = await self._raw_https_request(
                        ip, ssl_ctx, redirect_path,
                        method="POST",
                        host_header=redirect_host,
                        body=post_body,
                    )
                    break
                except (OSError, asyncio.TimeoutError) as e:
                    last_exc = e
                    continue

        return resp_raw

    async def _raw_https_request(self, connect_host, ssl_ctx, path, *, method="POST", host_header, body=None):
        """Make a single HTTPS request via domain-fronting (SNI=front_domain, Host=host_header).

        connect_host: IP or hostname to TCP-connect to
        path: URL path (and query) to request
        method: HTTP method string
        host_header: value for the HTTP Host header
        body: bytes body (None for GET)
        """
        connect_timeout = min(10, self._relay_timeout)

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                connect_host, 443,
                ssl=ssl_ctx,
                server_hostname=self._front_domain,
            ),
            timeout=connect_timeout,
        )

        if body is not None:
            req_lines = [
                f"{method} {path} HTTP/1.1",
                f"Host: {host_header}",
                f"Content-Type: application/json",
                f"Content-Length: {len(body)}",
                f"Accept-Encoding: identity",
                f"Connection: close",
                "",
                "",
            ]
            http_req = "\r\n".join(req_lines).encode() + body
        else:
            req_lines = [
                f"{method} {path} HTTP/1.1",
                f"Host: {host_header}",
                f"Accept-Encoding: identity",
                f"Connection: close",
                "",
                "",
            ]
            http_req = "\r\n".join(req_lines).encode()

        writer.write(http_req)
        await writer.drain()

        resp_raw = b""
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=self._relay_timeout)
            if not chunk:
                break
            resp_raw += chunk

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        return resp_raw


async def _read_http_request(reader: asyncio.StreamReader):
    """Read a complete HTTP request from the stream.

    Reads headers until CRLFCRLF, then reads the body based on Content-Length.
    Raises EOFError if the connection is closed before a complete request arrives.
    Returns (method, path, headers_dict, body).
    """
    # Accumulate header bytes until we see the end-of-headers marker.
    header_buf = b""
    while True:
        chunk = await reader.read(4096)
        if not chunk:
            raise EOFError("Connection closed before complete HTTP request")
        header_buf += chunk
        sep = header_buf.find(b"\r\n\r\n")
        if sep != -1:
            break

    header_section_raw = header_buf[:sep]
    remainder = header_buf[sep + 4:]

    # Parse request line and headers.
    try:
        header_section = header_section_raw.decode("utf-8", errors="replace")
        lines = header_section.split("\r\n")
        request_line = lines[0]
        parts = request_line.split(" ", 2)
        method = parts[0] if len(parts) > 0 else "GET"
        path = parts[1] if len(parts) > 1 else "/"

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()
    except Exception:
        return "GET", "/", {}, b""

    # Read body: honour Transfer-Encoding: chunked if present, otherwise use Content-Length.
    transfer_enc = headers.get("Transfer-Encoding", "").lower()
    content_length_str = headers.get("Content-Length", "")

    if "chunked" in transfer_enc:
        body = await _read_chunked_body(reader, remainder)
    elif content_length_str:
        try:
            content_length = int(content_length_str)
        except (ValueError, TypeError):
            content_length = 0
        body = remainder
        while len(body) < content_length:
            chunk = await reader.read(min(65536, content_length - len(body)))
            if not chunk:
                break
            body += chunk
        body = body[:content_length]
    else:
        body = b""

    return method, path, headers, body


def _build_http_response(gas_raw: bytes) -> bytes:
    """Parse GAS HTTP response, extract JSON body, build HTTP response bytes for client."""
    try:
        header_end = gas_raw.find(b"\r\n\r\n")
        if header_end == -1:
            log.debug("GAS raw response (no header end found): %r", gas_raw[:512])
            return b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"

        gas_headers_raw = gas_raw[:header_end]
        body_raw = gas_raw[header_end + 4:]

        # Follow redirects: if GAS returns 301/302/303/307/308, re-use the Location.
        # (Shouldn't normally happen for POST /exec, but guard against it.)
        first_line = gas_headers_raw.split(b"\r\n", 1)[0]
        status_parts = first_line.split(b" ", 2)
        http_status = int(status_parts[1]) if len(status_parts) >= 2 and status_parts[1].isdigit() else 200
        if http_status in (301, 302, 303, 307, 308):
            log.warning(
                "GAS returned redirect %d — redirect should have been followed; "
                "raw response: %r",
                http_status, gas_raw[:1024],
            )

        # Handle chunked transfer encoding (case-insensitive).
        if b"transfer-encoding: chunked" in gas_headers_raw.lower():
            body_raw = _decode_chunked(body_raw)

        # Decompress gzip if present (GAS sends gzip by default unless we ask for identity).
        # Detected by magic bytes \x1f\x8b regardless of Content-Encoding header.
        if body_raw[:2] == b"\x1f\x8b":
            try:
                body_raw = gzip.decompress(body_raw)
            except Exception as gz_err:
                log.debug("gzip decompress failed: %s", gz_err)

        json_body = body_raw.decode("utf-8", errors="replace").strip()

        if not json_body:
            log.warning("GAS returned empty body -- raw response: %r", gas_raw[:1024])
            return b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: 21\r\n\r\nEmpty GAS response body"

        data = json.loads(json_body)

        if "e" in data:
            err_msg = data["e"].encode()
            return (
                b"HTTP/1.1 502 Bad Gateway\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: " + str(len(err_msg)).encode() + b"\r\n"
                b"\r\n" + err_msg
            )

        status = data.get("s", 200)
        body_b64 = data.get("b", "")
        resp_headers = data.get("h", {})

        body = base64.b64decode(body_b64) if body_b64 else b""

        reason = REASON_PHRASES.get(status, "Unknown")
        lines = [f"HTTP/1.1 {status} {reason}\r\n".encode()]
        for k, v in resp_headers.items():
            k_lower = k.lower()
            if k_lower in ("transfer-encoding", "content-encoding"):
                continue  # body is already decoded/decompressed
            lines.append(f"{k}: {v}\r\n".encode())
        lines.append(f"Content-Length: {len(body)}\r\n".encode())
        lines.append(b"\r\n")
        lines.append(body)

        return b"".join(lines)

    except Exception as e:
        log.warning("Failed to parse GAS response: %s -- raw (first 1024 bytes): %r", e, gas_raw[:1024])
        return b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"


def _decode_chunked(data: bytes) -> bytes:
    """Decode HTTP chunked transfer encoding."""
    result = b""
    while data:
        crlf = data.find(b"\r\n")
        if crlf == -1:
            break
        # Chunk size line may contain extensions after a semicolon, e.g. "1a; ext=val"
        size_part = data[:crlf].split(b";", 1)[0].strip()
        try:
            size = int(size_part, 16)
        except ValueError:
            break
        if size == 0:
            break
        chunk_start = crlf + 2
        result += data[chunk_start:chunk_start + size]
        data = data[chunk_start + size + 2:]
    return result


async def _read_chunked_body(reader: asyncio.StreamReader, initial_data: bytes) -> bytes:
    """Read and decode an HTTP chunked-encoded body from reader.

    initial_data contains any bytes already buffered after the headers section.
    """
    buf = initial_data
    result = b""

    while True:
        # Ensure we have at least one complete chunk-size line in the buffer.
        while b"\r\n" not in buf:
            more = await reader.read(4096)
            if not more:
                break
            buf += more

        crlf = buf.find(b"\r\n")
        if crlf == -1:
            break

        size_part = buf[:crlf].split(b";", 1)[0].strip()
        try:
            size = int(size_part, 16)
        except ValueError:
            log.warning("_read_chunked_body: invalid chunk size %r, returning partial body", size_part)
            break

        if size == 0:
            break

        buf = buf[crlf + 2:]

        # Read until we have the full chunk data + trailing CRLF.
        while len(buf) < size + 2:
            more = await reader.read(min(65536, size + 2 - len(buf)))
            if not more:
                break
            buf += more

        result += buf[:size]
        buf = buf[size + 2:]

    return result


def _parse_redirect(resp_raw: bytes):
    """Return (status_code, location_url) if the response is a redirect, else (status_code, None)."""
    header_end = resp_raw.find(b"\r\n\r\n")
    if header_end == -1:
        return 0, None
    headers_raw = resp_raw[:header_end]
    lines = headers_raw.split(b"\r\n")
    first = lines[0].split(b" ", 2)
    try:
        status = int(first[1])
    except (IndexError, ValueError):
        return 0, None
    if status not in (301, 302, 303, 307, 308):
        return status, None
    for line in lines[1:]:
        if line.lower().startswith(b"location:"):
            location = line.split(b":", 1)[1].strip().decode("utf-8", errors="replace")
            return status, location
    return status, None
