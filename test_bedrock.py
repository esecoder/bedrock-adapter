"""
test_bedrock.py — every part of the adapter that can be checked without an AWS account.

    python3 test_bedrock.py
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import bedrock as B

FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{'  — ' + detail if detail else ''}")
    if not ok:
        FAILURES.append(name)


def main() -> int:
    print("test_bedrock.py — the Bedrock contract, offline\n")

    # ── 1. ⚠️ SIGV4 AGAINST AWS'S PUBLISHED TEST VECTOR ──────────────────────
    #
    # ⚠️ THIS IS THE ONLY SIGNING CHECK WORTH HAVING. Asserting that `sign_request`
    # returns the same thing twice proves the function is deterministic and nothing
    # else — a signature that is consistently WRONG passes that test perfectly.
    # AWS publishes the expected signature for a known request; comparing against it
    # is the difference between "it runs" and "it is correct".
    #
    # The `get-vanilla` case from the AWS SigV4 test suite:
    #   GET /   Host: example.amazonaws.com   X-Amz-Date: 20150830T123600Z
    #   credential scope 20150830/us-east-1/service/aws4_request
    aws_secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    aws_date, aws_region, aws_service = "20150830", "us-east-1", "service"

    headers = {"host": "example.amazonaws.com", "x-amz-date": "20150830T123600Z"}
    cr = B.canonical_request("GET", "/", {}, headers, b"")
    expected_cr = (
        "GET\n/\n\n"
        "host:example.amazonaws.com\n"
        "x-amz-date:20150830T123600Z\n\n"
        "host;x-amz-date\n"
        + hashlib.sha256(b"").hexdigest()
    )
    check("canonical request matches AWS's documented form", cr == expected_cr,
          "headers lower-cased, sorted, whitespace collapsed, blank line before SignedHeaders")

    scope = f"{aws_date}/{aws_region}/{aws_service}/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", "20150830T123600Z", scope,
                     hashlib.sha256(cr.encode()).hexdigest()])
    key = B.signing_key(aws_secret, aws_date, aws_region, aws_service)
    sig = hmac.new(key, sts.encode(), hashlib.sha256).hexdigest()

    # ⚠️ The signature AWS documents for this exact request.
    AWS_EXPECTED = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    check("SigV4 signature matches AWS's published test vector", sig == AWS_EXPECTED,
          f"got {sig[:16]}… want {AWS_EXPECTED[:16]}…" if sig != AWS_EXPECTED else sig[:16] + "…")

    check("the signing key is derived, not the secret itself",
          key != aws_secret.encode() and len(key) == 32,
          "four HMAC rounds: date, region, service, terminator")

    # ── 2. the wire format ──────────────────────────────────────────────────
    claude, titan = B.MODELS["claude-3-5-sonnet"], B.MODELS["titan-text"]

    host, path = B.build_url(claude, "us-east-1")
    check("the model id is in the PATH, not the body", "claude-3-5" in path and path.endswith("/invoke"),
          path[:52])
    check("the host carries the region", host == "bedrock-runtime.us-east-1.amazonaws.com")
    check("the model id is URL-encoded",
          ":" not in path and "%3A" in path,
          "an unencoded colon produces a 404 that reads like a missing model")

    cb = json.loads(B.build_body(claude, "hello"))
    tb = json.loads(B.build_body(titan, "hello"))
    check("the anthropic body carries anthropic_version",
          cb.get("anthropic_version") == "bedrock-2023-05-31",
          "required, and the easiest field to omit")
    check("the two families send DIFFERENT bodies",
          "messages" in cb and "inputText" in tb and "messages" not in tb,
          "Bedrock is a router in front of several APIs, not one API")

    check("the anthropic envelope unwraps content blocks",
          B.parse_response(claude, {"content": [{"type": "text", "text": "a"},
                                                {"type": "text", "text": "b"}]}) == "ab")
    check("the titan envelope unwraps results[0].outputText",
          B.parse_response(titan, {"results": [{"outputText": "hi"}]}) == "hi")

    # ── 3. the error taxonomy ───────────────────────────────────────────────
    # ⚠️ The distinction that matters: retryable and fatal need OPPOSITE handling.
    check("throttling is retryable",
          isinstance(B.parse_error(429, {"message": "slow down"}), B.BedrockThrottled))
    check("throttling is detected in the BODY too",
          isinstance(B.parse_error(400, {"__type": "ThrottlingException", "message": "x"}),
                     B.BedrockThrottled),
          "⚠️ it arrives as 429 AND as 400 with a throttling body — classifying on status "
          "alone would call it a validation error and never retry")
    check("a validation error is NOT retryable",
          isinstance(B.parse_error(400, {"__type": "ValidationException", "message": "bad"}),
                     B.BedrockValidation))
    check("a 5xx is transient",
          isinstance(B.parse_error(503, {"message": "unavailable"}), B.BedrockTransient))
    check("the code is read from the namespaced __type",
          "ValidationException" in str(B.parse_error(
              400, {"__type": "com.amazon.coral.validate#ValidationException", "message": "b"})),
          "__type arrives namespaced with a # separator")

    # ── 4. the whole path, through a stubbed transport ──────────────────────
    calls = []

    def stub_ok(host, path, headers, payload):
        calls.append({"path": path, "headers": headers, "payload": payload})
        return 200, {"content": [{"type": "text", "text": "from the stub"}]}

    out = B.invoke(claude, "hello", "us-east-1", stub_ok)
    check("invoke returns the parsed text", out == "from the stub")
    check("the request was signed before it was sent",
          "authorization" in calls[0]["headers"]
          and calls[0]["headers"]["authorization"].startswith("AWS4-HMAC-SHA256 Credential="),
          "an unsigned Bedrock request is a 403")
    check("SignedHeaders lists every header that was signed",
          "host;x-amz-date" in calls[0]["headers"]["authorization"],
          "a header sent but not signed is rejected")

    def stub_throttle(host, path, headers, payload):
        return 429, {"message": "rate exceeded"}

    try:
        B.invoke(claude, "hello", "us-east-1", stub_throttle)
        check("a throttled invoke raises", False, "it returned")
    except B.BedrockThrottled:
        check("a throttled invoke raises a RETRYABLE error", True)

    def stub_bad(host, path, headers, payload):
        return 400, {"__type": "ValidationException", "message": "too many tokens"}

    try:
        B.invoke(claude, "hello", "us-east-1", stub_bad)
        check("a malformed invoke raises", False, "it returned")
    except B.BedrockValidation:
        check("a malformed invoke raises a FATAL error", True, "so it is not retried forever")

    print()
    if FAILURES:
        print(f"  ❌ {len(FAILURES)} failed: {', '.join(FAILURES)}")
        return len(FAILURES)
    print("  ✅ the contract holds")
    print("  ⚠️ and nothing here has called the real service — it needs credentials")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
