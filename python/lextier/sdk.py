"""LexTier Python SDK (spec §9) — snake_case methods mapping one-to-one to §8
routes. Never caches approvals, never dispatches tools directly, never
auto-retries effects, never supplies tenant identity."""

import secrets
import urllib.error
import urllib.request

from .canonical import canonical_bytes
from .strictjson import parse_json_bytes


class LexTierError(Exception):
    def __init__(self, code, status=0, retryable=False, action_id=None, message=None):
        super().__init__(message or code)
        self.code = code
        self.status = status
        self.retryable = retryable
        self.action_id = action_id


def _idem_key() -> str:
    return secrets.token_urlsafe(24)


class LexTierClient:
    def __init__(self, base_url: str, token: str, timeout_ms: int = 10000):
        import re
        if not re.match(r"^https?://[A-Za-z0-9._:-]+$", base_url):
            raise LexTierError("SCHEMA_INVALID", message="bad base_url")
        if not isinstance(token, str) or not token:
            raise LexTierError("UNAUTHENTICATED", message="empty token")
        self._base = base_url
        self._token = token
        self._timeout = timeout_ms / 1000.0

    def _req(self, method: str, path: str, body=None, idem=False, query=None):
        if query:
            from urllib.parse import urlencode
            path = path + "?" + urlencode(query)
        headers = {"Authorization": f"Bearer {self._token}"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = canonical_bytes(body)
        if idem:
            headers["Idempotency-Key"] = _idem_key()
        request = urllib.request.Request(self._base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as res:
                raw = res.read()
                replayed = res.headers.get("Idempotency-Replayed") == "true"
                status = res.status
        except urllib.error.HTTPError as e:
            raw = e.read()
            status = e.code
            replayed = False
        except Exception as e:
            raise LexTierError("DEPENDENCY_UNAVAILABLE", retryable=True, message=str(e))
        parsed = parse_json_bytes(raw) if raw else None
        if status >= 400:
            eo = (parsed or {}).get("error", {})
            raise LexTierError(eo.get("code", "INTERNAL"), status,
                               eo.get("retryable") is True, eo.get("action_id"))
        return status, parsed, replayed

    def status(self):
        return self._req("GET", "/v1/status")[1]

    def submit(self, call):
        status, body, replayed = self._req("POST", "/v1/actions", call, idem=True)
        return {"status": status, "body": body, "replayed": replayed}

    def get(self, action_id):
        return self._req("GET", f"/v1/actions/{action_id}")[1]

    def view(self, action_id, action_hash: str, card_id: str):
        return self._req("POST", f"/v1/actions/{action_id}/view",
                         {"action_hash": action_hash, "card_id": card_id})[1]

    def decide(self, action_id, decision_input):
        return self._req("POST", f"/v1/actions/{action_id}/decision", decision_input, idem=True)[1]

    def cancel(self, action_id, expected_revision: int, reason: str):
        return self._req("POST", f"/v1/actions/{action_id}/cancel",
                         {"expected_revision": expected_revision, "reason": reason}, idem=True)[1]

    def reconcile(self, action_id):
        return self._req("POST", f"/v1/actions/{action_id}/reconcile", {}, idem=True)[1]

    def policy_get(self):
        return self._req("GET", "/v1/policy")[1]

    def policy_put(self, expected_revision: int, policy):
        return self._req("PUT", "/v1/policy",
                         {"expected_revision": expected_revision, "policy": policy}, idem=True)[1]

    def evaluate(self, call):
        return self._req("POST", "/v1/policy/evaluate", call)[1]

    def audit_page(self, after: int, through=None, limit: int = 1000):
        q = {"after": str(after), "limit": str(limit)}
        if through is not None:
            q["through"] = str(through)
        return self._req("GET", "/v1/audit", query=q)[1]

    def evidence_get(self, hash_hex: str):
        return self._req("GET", f"/v1/evidence/{hash_hex}")[1]

    def stats(self, from_ms: int, to_ms: int, through_seq=None):
        q = {"from_ms": str(from_ms), "to_ms": str(to_ms)}
        if through_seq is not None:
            q["through_seq"] = str(through_seq)
        return self._req("GET", "/v1/reviewers/stats", query=q)[1]

    def reaudit_open(self, action_id: str, reviewer: str, reason: str):
        return self._req("POST", "/v1/re-audits",
                         {"action_id": action_id, "reviewer": reviewer, "reason": reason}, idem=True)[1]

    def reaudit_get(self, reaudit_id: str):
        return self._req("GET", f"/v1/re-audits/{reaudit_id}")[1]

    def reaudit_close(self, reaudit_id: str, verdict: str):
        return self._req("POST", f"/v1/re-audits/{reaudit_id}/verdict", {"verdict": verdict}, idem=True)[1]

    def rotate_key(self, expected_head_seq: int, new_key_id: str, new_public_key: str):
        return self._req("POST", "/v1/audit/rotate-key", {
            "expected_head_seq": expected_head_seq,
            "new_key_id": new_key_id,
            "new_public_key": new_public_key,
        }, idem=True)[1]
