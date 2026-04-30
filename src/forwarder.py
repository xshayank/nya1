"""
HTTPForwarder — listens on localhost:<listen_port>, reads incoming plain HTTP
requests, and relays them to the configured target via Google Apps Script
(domain-fronted through www.google.com).
"""

import asyncio
import base64
import json
import logging
import ssl
from urllib.parse import urlparse, urlunparse

log = logging.getLogger("Forwarder")


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
        try:
            while True:
                # Read the raw HTTP request (headers + body)
                try:
                    raw = await asyncio.wait_for(reader.read(65536), timeout=self._relay_timeout)
                except asyncio.TimeoutError:
                    log.debug("Idle timeout on connection from %s", peer)
                    break
                if not raw:
                    break

                # Parse the HTTP request line to get method and path
                method, path, headers_dict, body = _parse_http_request(raw)

                # Build target URL: use target base + request path
                parsed_target = urlparse(self._target_url)
                full_url = urlunparse((
                    parsed_target.scheme,
                    parsed_target.netloc,
                    path,
                    "", "", ""
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
        }
        if body:
            payload["b"] = base64.b64encode(body).decode()

        post_body = json.dumps(payload).encode()

        # Build TLS context for domain fronting
        # SNI = front_domain (e.g. www.google.com), Host = script.google.com
        ssl_ctx = ssl.create_default_context()

        connect_host = self._google_ip if self._google_ip else "script.google.com"

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    connect_host, 443,
                    ssl=ssl_ctx,
                    server_hostname=self._front_domain,
                ),
                timeout=self._relay_timeout,
            )

            http_req = (
                f"POST /macros/s/{script_id}/exec HTTP/1.1\r\n"
                f"Host: script.google.com\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(post_body)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode() + post_body

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

            # Parse GAS JSON response and build HTTP response bytes
            return _build_http_response(resp_raw)

        except Exception as e:
            log.error("GAS relay error: %s", e)
            return b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"


def _parse_http_request(raw: bytes):
    """Parse raw HTTP request bytes into (method, path, headers_dict, body)."""
    try:
        header_end = raw.find(b"\r\n\r\n")
        if header_end == -1:
            header_end = len(raw)
            body = b""
        else:
            body = raw[header_end + 4:]

        header_section = raw[:header_end].decode("utf-8", errors="replace")
        lines = header_section.split("\r\n")
        request_line = lines[0]
        parts = request_line.split(" ", 2)
        method = parts[0] if len(parts) > 0 else "GET"
        path = parts[1] if len(parts) > 1 else "/"

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()

        return method, path, headers, body
    except Exception:
        return "GET", "/", {}, b""


def _build_http_response(gas_raw: bytes) -> bytes:
    """Parse GAS HTTP response, extract JSON body, build HTTP response bytes for client."""
    try:
        header_end = gas_raw.find(b"\r\n\r\n")
        if header_end == -1:
            return b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"

        gas_headers_raw = gas_raw[:header_end]
        body_raw = gas_raw[header_end + 4:]

        # Handle chunked transfer encoding if present
        if (b"Transfer-Encoding: chunked" in gas_headers_raw
                or b"transfer-encoding: chunked" in gas_headers_raw.lower()):
            body_raw = _decode_chunked(body_raw)

        json_body = body_raw.decode("utf-8", errors="replace").strip()
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

        lines = [f"HTTP/1.1 {status} OK\r\n".encode()]
        for k, v in resp_headers.items():
            k_lower = k.lower()
            if k_lower in ("transfer-encoding", "content-encoding"):
                continue  # GAS already decoded
            lines.append(f"{k}: {v}\r\n".encode())
        lines.append(f"Content-Length: {len(body)}\r\n".encode())
        lines.append(b"\r\n")
        lines.append(body)

        return b"".join(lines)

    except Exception as e:
        log.error("Failed to parse GAS response: %s", e)
        return b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"


def _decode_chunked(data: bytes) -> bytes:
    """Decode HTTP chunked transfer encoding."""
    result = b""
    while data:
        crlf = data.find(b"\r\n")
        if crlf == -1:
            break
        try:
            size = int(data[:crlf], 16)
        except ValueError:
            break
        if size == 0:
            break
        chunk_start = crlf + 2
        result += data[chunk_start:chunk_start + size]
        data = data[chunk_start + size + 2:]
    return result
