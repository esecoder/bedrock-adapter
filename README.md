# bedrock-adapter

**The parts of a Bedrock integration that can be proved without an AWS account.**

```bash
python3 test_bedrock.py       # 20 checks, no dependencies
```

```
PASS  SigV4 signature matches AWS's published test vector  — 5fa00fa31553b73e…
PASS  throttling is detected in the BODY too
PASS  a validation error is NOT retryable
```

##  What this is not

**It is not "Bedrock experience."** Bedrock needs an AWS account, credentials and spend. **Nothing here has ever called the real service**, and the README says so rather than letting a green test suite imply otherwise.

## What it is

A correct implementation of the three things that cost time on a first integration:

**1. The wire format.**  Bedrock is **not the OpenAI API with a different URL** — it's a router in front of several. The model goes in the **path**, not the body; `anthropic_version` is required and trivially omitted; and the response arrives in a `content` envelope or a `results[0].outputText` envelope depending on family. Getting it wrong is a 400 with no useful message.

**2. SigV4 signing.**  **Verified against AWS's published test vector**, not against itself. Asserting that a signer returns the same value twice proves it's deterministic and nothing else — **a signature that is consistently wrong passes that perfectly.** The `get-vanilla` case from AWS's SigV4 suite matches on the first run.

**3. The error taxonomy.**  **This is the part that matters most**, and it's the same distinction the idempotency work makes:

| | |
|---|---|
| `ThrottlingException` | **retryable** — the request was fine, the account was busy |
| `ValidationException` | **fatal** — retrying sends the same wrong thing forever |
| 5xx | transient |

 **Throttling arrives as a 429 *and* as a 400 with a throttling body.** Classifying on the status line alone calls it a validation error and never retries.

**And the seam is the point.** `invoke()` takes a **transport** rather than calling `requests`, which is what makes every error path testable without an account.

## What is not covered

 Streaming (`invoke-with-response-stream`), guardrails, provisioned throughput, and VPC endpoints. The request/response contract and the failure handling are the minimum, and they are the minimum because they are what a first integration gets wrong.
