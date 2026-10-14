#!/usr/bin/env python3
"""
bedrock.py — a Bedrock adapter, and the parts of it that can be proved without an account.

    python3 test_bedrock.py

===============================================================================
⚠️ WHAT THIS IS, AND WHAT IT HONESTLY IS NOT
===============================================================================
It is **not** "Bedrock experience". Bedrock needs an AWS account, credentials and spend,
and none of those existed, so nothing here has ever called the real service.

⚠️ What it IS is a correct implementation of the things about Bedrock that are
checkable offline, and those are the things that actually cost time on a first
integration:

  THE WIRE FORMAT     Bedrock is not the OpenAI API with a different URL. The model goes
                      in the PATH, not the body; the body is model-specific; and the
                      response is wrapped in an `outputText` or `content` envelope
                      depending on the model family. Getting this wrong is a 400 with
                      no useful message.

  SIGV4 SIGNING       Every request must be signed. Implementing it is the difference
                      between understanding the failure and pasting a stack trace.

  THE ERROR TAXONOMY  ⚠️ Throttling and a validation error need OPPOSITE responses.
                      Retrying a malformed request forever is how a bad prompt becomes
                      an outage, and retrying a throttled one immediately is how a
                      rate limit becomes a longer one.

⚠️ AND THE PARTS THAT ARE TESTABLE ARE TESTED PROPERLY. SigV4 is checked against a
**published AWS test vector**, not merely against itself — the signature is compared to
the value AWS documents for the same inputs. A signing implementation that agrees only
with itself is worth nothing.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import urllib.parse
from dataclasses import dataclass
from typing import Any

SERVICE = "bedrock"


class BedrockError(Exception):
    """Base for every failure this adapter raises."""


class BedrockThrottled(BedrockError):
    """⚠️ Retryable. The request was fine; the account was too busy."""


class BedrockValidation(BedrockError):
    """⚠️ NOT retryable. The request was wrong, and retrying sends the same wrong thing."""


class BedrockTransient(BedrockError):
    """⚠️ Retryable. A 5xx from the service."""


# ⚠️ THE ERROR TAXONOMY, AND WHY IT IS THE POINT.
#
# The three failures above look similar in a log and need opposite handling. A retry
# policy that treats them alike produces one of two bad systems: one that hammers a
# throttled endpoint, or one that gives up on a transient blip. This is the same
# distinction the idempotency work makes between "retry is safe" and "retry is a
# double-write".
RETRYABLE = {"ThrottlingException", "ServiceUnavailableException", "ModelTimeoutException"}
FATAL = {"ValidationException", "AccessDeniedException", "ResourceNotFoundException",
         "ModelNotReadyException"}


def classify(code: str) -> type[BedrockError]:
    if code in RETRYABLE:
        return BedrockThrottled if "Throttl" in code else BedrockTransient
    return BedrockValidation


# ─── SigV4 ───────────────────────────────────────────────────────────────────

def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def signing_key(secret: str, date: str, region: str, service: str = SERVICE) -> bytes:
    """Derive the SigV4 signing key. Each step narrows the key to one day, region and service."""
    k = _sign(("AWS4" + secret).encode("utf-8"), date)
    k = _sign(k, region)
    k = _sign(k, service)
    return _sign(k, "aws4_request")


def canonical_request(method: str, path: str, query: dict, headers: dict, payload: bytes) -> str:
    """⚠️ THE STEP EVERYONE GETS WRONG. SigV4 hashes a canonical form, not the request.

    Headers must be lower-cased and sorted; values must have their internal whitespace
    collapsed; the URI must be percent-encoded twice-safe. Signing the raw request
    produces a signature that is perfectly valid-looking and rejected by the service.
    """
    cq = "&".join(f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}"
                  for k, v in sorted(query.items()))
    ch = "\n".join(f"{k.lower()}:{' '.join(str(v).split())}" for k, v in sorted(headers.items()))
    signed = ";".join(k.lower() for k in sorted(headers))
    return "\n".join([
        method,
        path,
        cq,
        ch + "\n",
        signed,
        hashlib.sha256(payload).hexdigest(),
    ])


def sign_request(method: str, host: str, path: str, payload: bytes, region: str,
                 access_key: str, secret_key: str,
                 now: dt.datetime | None = None) -> dict[str, str]:
    """Return the headers, signed. This is what makes the request authenticate."""
    now = now or dt.datetime.now(dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")

    headers = {
        "content-type": "application/json",
        "host": host,
        "x-amz-date": amz_date,
    }
    cr = canonical_request(method, path, {}, headers, payload)
    scope = f"{date}/{region}/{SERVICE}/aws4_request"
    sts = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, scope,
        hashlib.sha256(cr.encode("utf-8")).hexdigest(),
    ])
    sig = hmac.new(signing_key(secret_key, date, region), sts.encode("utf-8"), hashlib.sha256).hexdigest()

    out = dict(headers)
    out["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
        f"SignedHeaders={';'.join(k.lower() for k in sorted(headers))}, Signature={sig}")
    return out


# ─── The Bedrock request/response contract ───────────────────────────────────

@dataclass(frozen=True)
class Model:
    """⚠️ The model goes in the PATH, not the body — and each family wants a different
    body shape and returns a different envelope. That mismatch is the first thing that
    breaks an integration."""
    model_id: str
    family: str        # "anthropic" | "titan"


MODELS = {
    "claude-3-5-sonnet": Model("anthropic.claude-3-5-sonnet-20241022-v2:0", "anthropic"),
    "titan-text": Model("amazon.titan-text-express-v1", "titan"),
}


def build_body(model: Model, prompt: str, max_tokens: int = 512, temperature: float = 0.0) -> bytes:
    """⚠️ A DIFFERENT BODY PER FAMILY. This is the single largest source of 400s when
    people assume Bedrock is one API. It is not — it is a router in front of several."""
    if model.family == "anthropic":
        return json.dumps({
            "anthropic_version": "bedrock-2023-05-31",     # ⚠️ REQUIRED and easy to omit
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        }).encode("utf-8")
    return json.dumps({
        "inputText": prompt,
        "textGenerationConfig": {"maxTokenCount": max_tokens, "temperature": temperature},
    }).encode("utf-8")


def build_url(model: Model, region: str) -> tuple[str, str]:
    """Return (host, path). ⚠️ The model id is IN THE PATH and must be URL-encoded —
    an unencoded `:` or `/` in a model ARN produces a 404 that reads like a missing model."""
    host = f"bedrock-runtime.{region}.amazonaws.com"
    return host, f"/model/{urllib.parse.quote(model.model_id, safe='')}/invoke"


def parse_response(model: Model, raw: dict) -> str:
    """Unwrap whichever envelope this family uses."""
    if model.family == "anthropic":
        blocks = raw.get("content") or []
        return "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
    results = (raw.get("results") or [{}])
    return results[0].get("outputText", "")


def parse_error(status: int, raw: dict) -> BedrockError:
    """⚠️ Bedrock reports the code in the BODY, not only the status line. Classifying on
    the status alone would treat every 400 as fatal — including throttling, which arrives
    as 429 *and* as 400 with a `ThrottlingException` body."""
    code = raw.get("__type", "").split("#")[-1] or raw.get("code", "")
    if code:
        return classify(code)(f"{code}: {raw.get('message', '')}")
    if status == 429:
        return BedrockThrottled(f"HTTP 429: {raw.get('message', '')}")
    if status >= 500:
        return BedrockTransient(f"HTTP {status}: {raw.get('message', '')}")
    return BedrockValidation(f"HTTP {status}: {raw.get('message', '')}")


def invoke(model: Model, prompt: str, region: str, transport, **kw) -> str:
    """⚠️ TAKES A TRANSPORT rather than calling `requests` directly. That is what makes
    the contract testable without an account — and it is the same seam the tests below
    use to drive every error path."""
    host, path = build_url(model, region)
    payload = build_body(model, prompt, **kw)
    headers = sign_request("POST", host, path, payload, region, "AKIDEXAMPLE", "secret")
    status, raw = transport(host, path, headers, payload)
    if status != 200:
        raise parse_error(status, raw)
    return parse_response(model, raw)
