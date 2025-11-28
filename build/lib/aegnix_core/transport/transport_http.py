# aegnix_core/transport/transport_http.py
import requests, json, threading, os
from aegnix_core.logger import get_logger

log = get_logger("AE.Transport.HTTP")

class HTTPAdapter:
    """
    HTTP transport adapter for posting envelopes to the ABI /emit endpoint.

    Features:
    - Supports Bearer JWT authentication via AE_GRANT environment variable.
    - Supports SSE-based subscription for live topic streaming (Phase 3E).
    """
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.handlers = {}
        self._threads = []
        self._grant = None

    def set_grant(self, grant: str):
        """Stores the JWT provided by AEClient."""
        self._grant = grant

    # ------------------------------------------------------------------
    # Outbound publishing
    # ------------------------------------------------------------------
    def publish(self, subject: str, message: dict):
        """
        POST a signed envelope to the ABI /emit endpoint.
        Adds an Authorization header automatically if AE_GRANT is set.
        """
        url = f"{self.base_url}/emit"
        headers = {"Content-Type": "application/json"}

        # Bearer grant (session token from AEClient.register_with_abi)
        # grant = os.getenv("AE_GRANT")
        # if grant:
        #     headers["Authorization"] = f"Bearer {grant}"
        if self._grant:
            headers["Authorization"] = f"Bearer {self._grant}"

        log.debug(f"[HTTP PUB] → {url} | subject={subject}")
        log.info(f"[HTTP PUB subject] → {url} | subject={subject}")
        log.info(f"[HTTP PUB head] → {url} | headers={headers}")
        log.info(f"[HTTP PUB msg] → {url} | json_message={message}")
        try:
            res = requests.post(url, json=message, headers=headers, timeout=5)
            log.info(f"[HTTP PUB res] {res.status_code} {res.reason}")
            if res.ok:
                log.info(f"[HTTP PUB] {res.status_code} {res.reason}")
                return res.json()
            else:
                log.error(f"[HTTP PUB] {res.status_code}: {res.text}")
                return {"error": res.text, "status": res.status_code}
        except Exception as e:
            log.exception(f"[HTTP PUB] Exception: {e}")
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Inbound streaming (Server-Sent Events)
    # ------------------------------------------------------------------
    def _sse_reader(self, topic: str, handler, headers):
        """
        Ultra-reliable SSE reader that:
          - disables urllib3 buffer
          - forces raw chunk iteration
          - handles heartbeat + multiline data
        """

        url = f"{self.base_url}/subscribe/{topic}"
        log.info(f"[HTTP SUB] Connecting to SSE stream: {url}")

        try:
            with requests.get(
                    url,
                    headers=headers,
                    stream=True,
                    timeout=None,
            ) as r:

                # absolutely required for SSE
                r.raw.decode_content = True

                log.info(f"[HTTP SUB] Connected to {url} status={r.status_code}")

                event_lines = []

                for raw in r.raw:
                    try:
                        log.debug(f"[HTTP SUB] raw {raw}")
                        line = raw.decode("utf-8").rstrip("\r\n")
                        log.debug(f"[HTTP SUB] line to {line}")
                    except Exception as e:
                        log.error(f"[HTTP SUB] decode error {e}")
                        continue

                    # --- debug raw lines ---
                    log.debug(f"[HTTP SUB] raw line: {line!r}")
                    # log.info(f"[HTTP SUB] raw line: {line!r}")

                    # blank line = dispatch event
                    if line == "":
                        if event_lines:
                            try:
                                data_parts = [
                                    l[5:].lstrip()
                                    for l in event_lines
                                    if l.startswith("data:")
                                ]
                                data_str = "\n".join(data_parts)

                                log.debug(f"[HTTP SUB] assembled event: {data_str}")
                                # log.info(f"[HTTP SUB] assembled event: {data_str}")
                                payload = json.loads(data_str)
                                handler(payload)
                            except Exception as e:
                                log.error(f"[SSE parse error] {e}")
                            event_lines = []
                        continue

                    # heartbeat
                    if line.startswith(":"):
                        log.debug(f"[HTTP SUB] heartbeat {line!r}")
                        # log.info(f"[HTTP SUB] heartbeat {line!r}")
                        continue

                    # data line
                    if line.startswith("data:"):
                        event_lines.append(line)

        except Exception as e:
            log.error(f"[SSE connection error] {e}")

        finally:
            log.info(f"[HTTP SUB] SSE loop ended for {topic}")

    def subscribe(self, subject: str, handler):
        """
        Subscribe to a topic stream via SSE (Server-Sent Events).

        Spawns a background thread that listens for messages from
        /subscribe/{subject} and invokes the handler on each one.
        """

        headers = {}
        if self._grant:
            headers["Authorization"] = f"Bearer {self._grant}"

        self.handlers[subject] = handler
        log.info(f"[HTTP SUB] Subscribing to {subject}")

        t = threading.Thread(target=self._sse_reader, args=(subject, handler, headers), daemon=True)
        t.start()
        self._threads.append(t)
