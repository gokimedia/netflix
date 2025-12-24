#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security_compliance_test.py (v2.0) - Enterprise-Grade Access Control Regression Suite (Async)

This is a QA / CI-oriented regression suite that validates **expected** authorization outcomes
(allow/deny) across one or many targets, at high speed, using fully async HTTP I/O.

✅ What this suite DOES (safe, regression-focused)
- Runs *explicitly defined* access-control test cases (e.g., "User A must NOT access User B resource")
- High concurrency with asyncio + httpx (non-blocking)
- Resilient network layer (retry + exponential backoff + jitter on transient failures)
- Heuristic test-vector factory (ID type inference) for **validation & robustness** cases
  - "malformed", "missing", "random UUID" etc.
  - Optional numeric BVA vectors can be enabled explicitly (off by default)
- Produces JSON and HTML reports suitable for dashboards
- Returns a non-zero exit code on failures (CI-friendly)

⛔ What this suite intentionally does NOT do
- No endpoint crawling / discovery
- No exploit/bypass payloads (encoding bypass, HPP, method override tunneling, etc.)
- No "scan the world" behavior

Why: this is meant to *verify a patch/regression* under known, authorized conditions.

------------------------------------------------------------
Install:
  pip install httpx

Quick run (env-driven, single case):
  export TARGETS="https://site-a.example.com,https://site-b.example.com"
  export USER_A_TOKEN="Bearer <tokenA>"
  export USER_A_ID="122"
  export USER_B_ID="123"
  export ENDPOINT_TEMPLATE="/api/users/{user_id}"
  python security_compliance_test.py --run --concurrency 100 --timeout 10

Preferred run (config-driven):
  python security_compliance_test.py --config ac_suite.json --run

Example config (ac_suite.json):
{
  "targets": ["https://site-a.example.com", "https://site-b.example.com"],
  "auth_header": "Authorization",
  "principals": {
    "userA": {"token_env": "USER_A_TOKEN", "id_env": "USER_A_ID"},
    "userB": {"token_env": "USER_B_TOKEN", "id_env": "USER_B_ID"}
  },
  "defaults": {
    "deny_status": [403, 404],
    "allow_status": [200]
  },
  "cases": [
    {
      "name": "user_profile_read",
      "method": "GET",
      "path_template": "/api/users/{user_id}",
      "placeholders": ["user_id"],

      "allow": { "principal": "userA", "placeholder_values": {"user_id": "self"} },

      "deny": [
        { "principal": "userA", "placeholder_values": {"user_id": "userB"} }
      ],

      "sensitive_markers": ["email", "ssn"],
      "extra_vectors": ["malformed", "missing", "random"],

      "enable_numeric_bva": false
    }
  ]
}

Notes:
- Many production systems intentionally return 404 instead of 403 to reduce enumeration risk.
  Use deny_status [403,404] in config if that's your policy.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import importlib
import importlib.util
import json
import os
import random
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Callable
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse

try:
    import httpx
except ImportError as e:
    raise SystemExit("Missing dependency: httpx. Install with: pip install httpx") from e


# -----------------------------
# Console colors (optional)
# -----------------------------
class C:
    FAIL = "\033[91m"
    PASS = "\033[92m"
    WARN = "\033[93m"
    INFO = "\033[94m"
    BOLD = "\033[1m"
    END = "\033[0m"


def utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def clamp(n: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, n))


def safe_snippet(text: str, n: int = 500) -> str:
    return (text or "")[:n]


# -----------------------------
# ID heuristics (safe vectors)
# -----------------------------
_ID_PATTERNS = {
    "numeric": re.compile(r"^\d+$"),
    "uuid": re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I),
    "uuid_nodash": re.compile(r"^[0-9a-f]{32}$", re.I),
    "mongo": re.compile(r"^[0-9a-f]{24}$", re.I),
    "hash_hex": re.compile(r"^[0-9a-f]{40,64}$", re.I),  # sha1/sha256-ish (coarse)
    "alnum": re.compile(r"^[a-zA-Z0-9]+$"),
}


def infer_id_type(value: str) -> str:
    if not value:
        return "unknown"
    for name, pat in _ID_PATTERNS.items():
        if pat.match(value):
            # prefer uuid over hash if dashed
            if name == "hash_hex" and _ID_PATTERNS["uuid_nodash"].match(value):
                return "uuid_nodash"
            return name
    return "unknown"


def rand_hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def rand_alnum(n: int) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(random.choice(alphabet) for _ in range(n))


class PayloadFactory:
    """
    Generates **safe** regression vectors based on an observed ID.
    Purpose: validate input handling & policy (deny/allow), not "bypass".

    Vectors:
      - malformed: wrong type/format (e.g., "abc" for numeric, "not-a-uuid" for uuid)
      - missing: empty string (caller may omit the parameter)
      - random: random UUID/alnum of similar shape
      - numeric_bva (opt-in): -1, 0, huge number, non-numeric
    """

    @staticmethod
    def vectors_for_id(observed: str, enable_numeric_bva: bool = False) -> Dict[str, Optional[str]]:
        t = infer_id_type(observed)
        out: Dict[str, Optional[str]] = {}

        # missing => None means "remove" the placeholder (handled by renderer)
        out["missing"] = None

        if t == "numeric":
            out["malformed"] = "not-a-number"
            out["random"] = str(random.randint(10**9, 10**10 - 1))  # large random
            if enable_numeric_bva:
                out["numeric_bva_-1"] = "-1"
                out["numeric_bva_0"] = "0"
                out["numeric_bva_huge"] = str(2**63 - 1)
                out["numeric_bva_alpha"] = "abc"
        elif t in ("uuid",):
            out["malformed"] = "not-a-uuid"
            # random UUID v4
            import uuid as _uuid
            out["random"] = str(_uuid.uuid4())
        elif t in ("uuid_nodash",):
            out["malformed"] = "Z" * 32
            out["random"] = rand_hex(32)
        elif t == "mongo":
            out["malformed"] = "g" * 24
            out["random"] = rand_hex(24)
        elif t == "hash_hex":
            out["malformed"] = "x" * len(observed)
            out["random"] = rand_hex(len(observed))
        elif t == "alnum":
            out["malformed"] = "!@#$"
            out["random"] = rand_alnum(len(observed))
        else:
            out["malformed"] = "!!invalid!!"
            out["random"] = rand_alnum(12)

        return out


# -----------------------------
# Configuration model
# -----------------------------
@dataclass(frozen=True)
class Principal:
    name: str
    token: str
    user_id: Optional[str] = None


@dataclass(frozen=True)
class CaseExpectation:
    principal: str
    placeholder_values: Dict[str, str]  # "self" | "<principalName>" | "static:<value>" | "env:VAR"
    expected_status: Optional[List[int]] = None  # if None, use defaults
    # Optional transformation layer (data-driven). Provide a strategy name or list of names.
    # Implementations may be built-in (safe) or provided via a local plugin (see --transformer-plugin).
    transformation_strategy: Optional[Union[str, List[str]]] = None
    transformation_args: Optional[Dict[str, Any]] = None

@dataclass(frozen=True)
class TestCase:
    name: str
    method: str
    path_template: str
    placeholders: List[str]
    allow: Optional[CaseExpectation] = None
    deny: Optional[List[CaseExpectation]] = None
    headers: Optional[Dict[str, str]] = None
    json_body: Optional[Any] = None
    data_body: Optional[Any] = None
    allow_status: Optional[List[int]] = None
    deny_status: Optional[List[int]] = None
    sensitive_markers: Optional[List[str]] = None
    extra_vectors: Optional[List[str]] = None  # e.g. ["malformed","missing","random"]
    enable_numeric_bva: bool = False


@dataclass(frozen=True)
class SuiteConfig:
    targets: List[str]
    auth_header: str
    principals: Dict[str, Principal]
    cases: List[TestCase]
    defaults_allow_status: List[int]
    defaults_deny_status: List[int]
    insecure_tls: bool


# -----------------------------
# Result model
# -----------------------------
@dataclass
class TestResult:
    target: str
    case: str
    vector: str  # allow/deny/malformed/missing/random...
    method: str
    url: str
    principal: str
    expected_status: List[int]
    actual_status: Optional[int]
    ok: bool
    latency_ms: float
    transformations: Optional[List[str]] = None
    error: Optional[str] = None
    request_id: Optional[str] = None
    evidence_snippet: Optional[str] = None
    leaked_markers: Optional[List[str]] = None




# -----------------------------
# Transformation layer (data-driven, plugin-capable)
# -----------------------------
@dataclass(frozen=True)
class RequestSpec:
    method: str
    url: str
    headers: Dict[str, str]
    json_body: Any = None
    data_body: Any = None


@dataclass(frozen=True)
class TransformContext:
    target: str
    case: str
    vector: str
    principal: str
    args: Dict[str, Any]


TransformerFn = Callable[[RequestSpec, TransformContext], RequestSpec]


class RestrictedTransformationError(RuntimeError):
    pass


# NOTE:
# We intentionally do not ship built-in transformations that emulate security bypass vectors
# (e.g., double-encoding, HPP duplication, method-override tunneling).
# If your organization has an approved internal policy test pack for these behaviors,
# provide them via --transformer-plugin to keep this suite generic and safe.
RESTRICTED_STRATEGIES = {
    "double_encode",
    "hpp_duplicate",
    "method_override",
}


def _tx_add_trace_id(spec: RequestSpec, ctx: TransformContext) -> RequestSpec:
    header_name = str(ctx.args.get("header", "X-Trace-Id"))
    new_headers = dict(spec.headers)
    new_headers[header_name] = str(uuid.uuid4())
    return dataclasses.replace(spec, headers=new_headers)


def _tx_cache_bust(spec: RequestSpec, ctx: TransformContext) -> RequestSpec:
    param = str(ctx.args.get("param", "cb"))
    # Append a cache-busting query parameter (benign).
    u = urlparse(spec.url)
    q = parse_qsl(u.query, keep_blank_values=True)
    q.append((param, f"{int(time.time()*1000)}{rand_alnum(4)}"))
    new_url = urlunparse((u.scheme, u.netloc, u.path, u.params, urlencode(q, doseq=True), u.fragment))
    return dataclasses.replace(spec, url=new_url)


def load_transformers_from_plugin(plugin_ref: Optional[str]) -> Dict[str, TransformerFn]:
    """Load TRANSFORMERS registry from a python module or a .py file path.

    Plugin contract:
      - Provide a dict named TRANSFORMERS: { "name": callable }
      - Callable signature: (spec: RequestSpec, ctx: TransformContext) -> RequestSpec
    """
    if not plugin_ref:
        return {}

    plugin_ref = plugin_ref.strip()
    if not plugin_ref:
        return {}

    # Support both module path and file path
    mod = None
    if plugin_ref.endswith(".py") and os.path.exists(plugin_ref):
        spec = importlib.util.spec_from_file_location("ac_transformer_plugin", plugin_ref)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    else:
        mod = importlib.import_module(plugin_ref)

    if not mod or not hasattr(mod, "TRANSFORMERS"):
        raise ValueError("Transformer plugin must define TRANSFORMERS dict")

    reg = getattr(mod, "TRANSFORMERS")
    if not isinstance(reg, dict):
        raise ValueError("TRANSFORMERS must be a dict[str, callable]")

    out: Dict[str, TransformerFn] = {}
    for k, v in reg.items():
        if not isinstance(k, str) or not callable(v):
            continue
        out[k] = v  # trust user's internal plugin
    return out


def build_transformer_registry(plugin_ref: Optional[str]) -> Dict[str, TransformerFn]:
    registry: Dict[str, TransformerFn] = {
        # built-in benign helpers
        "add_trace_id": _tx_add_trace_id,
        "cache_bust": _tx_cache_bust,
    }
    registry.update(load_transformers_from_plugin(plugin_ref))
    return registry


def normalize_strategy_list(strategy: Optional[Union[str, List[str]]]) -> List[str]:
    if not strategy:
        return []
    if isinstance(strategy, str):
        return [strategy]
    if isinstance(strategy, list):
        return [s for s in strategy if isinstance(s, str) and s.strip()]
    return []


def apply_transformations(
    spec: RequestSpec,
    target: str,
    case: str,
    vector: str,
    principal: str,
    strategy: Optional[Union[str, List[str]]],
    strategy_args: Optional[Dict[str, Any]],
    registry: Dict[str, TransformerFn],
) -> Tuple[RequestSpec, List[str]]:
    strategies = normalize_strategy_list(strategy)
    if not strategies:
        return spec, []

    used: List[str] = []
    args = dict(strategy_args or {})

    for sname in strategies:
        sname = sname.strip()
        if not sname:
            continue

        if sname in RESTRICTED_STRATEGIES and sname not in registry:
            raise RestrictedTransformationError(
                f"Transformation strategy '{sname}' is restricted and not provided. "
                "Provide an approved internal implementation via --transformer-plugin."
            )

        fn = registry.get(sname)
        if not fn:
            raise ValueError(f"Unknown transformation_strategy: {sname}")

        ctx = TransformContext(target=target, case=case, vector=vector, principal=principal, args=args)
        spec = fn(spec, ctx)
        used.append(sname)

    return spec, used

# -----------------------------
# HTTP layer with retries
# -----------------------------
class AsyncRequester:
    def __init__(
        self,
        timeout_s: float,
        retries: int,
        backoff_base: float,
        backoff_cap: float,
        insecure_tls: bool,
    ):
        self.timeout_s = timeout_s
        self.retries = max(0, retries)
        self.backoff_base = max(0.05, backoff_base)
        self.backoff_cap = max(self.backoff_base, backoff_cap)
        self.insecure_tls = insecure_tls

    async def request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        headers: Dict[str, str],
        json_body: Any,
        data_body: Any,
    ) -> Tuple[Optional[int], float, Dict[str, str], str, Optional[str]]:
        """
        Returns: (status_code, latency_ms, response_headers, response_text, request_id)
        Retries on: connect errors, timeouts, 5xx, 429
        """
        attempt = 0
        last_exc: Optional[Exception] = None

        while attempt <= self.retries:
            t0 = time.perf_counter()
            try:
                resp = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=json_body if json_body is not None else None,
                    data=data_body if data_body is not None else None,
                    timeout=self.timeout_s,
                )
                latency_ms = (time.perf_counter() - t0) * 1000.0

                # attempt to extract request id for debugging
                rid = (
                    resp.headers.get("x-request-id")
                    or resp.headers.get("x-correlation-id")
                    or resp.headers.get("traceparent")
                )

                # Retry on transient responses
                if resp.status_code in (429,) or (500 <= resp.status_code <= 599):
                    if attempt < self.retries:
                        await self._sleep_backoff(attempt)
                        attempt += 1
                        continue

                return resp.status_code, latency_ms, dict(resp.headers), resp.text, rid

            except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout, httpx.ConnectTimeout) as e:
                last_exc = e
                if attempt < self.retries:
                    await self._sleep_backoff(attempt)
                    attempt += 1
                    continue
                latency_ms = (time.perf_counter() - t0) * 1000.0
                return None, latency_ms, {}, "", None

            except Exception as e:
                last_exc = e
                latency_ms = (time.perf_counter() - t0) * 1000.0
                return None, latency_ms, {}, "", None

        # Should not reach
        return None, 0.0, {}, "", None

    async def _sleep_backoff(self, attempt: int) -> None:
        # exponential backoff + jitter
        base = min(self.backoff_cap, self.backoff_base * (2 ** attempt))
        jitter = random.random() * 0.25 * base
        await asyncio.sleep(base + jitter)


# -----------------------------
# Rendering placeholders
# -----------------------------
def resolve_placeholder_value(
    token: str,
    placeholder: str,
    principals: Dict[str, Principal],
    current_principal: Principal,
) -> Optional[str]:
    """
    token can be:
      - "self" => current principal user_id
      - "<principalName>" => that principal user_id
      - "static:<value>"
      - "env:VAR"
      - otherwise treated as literal
    Return None to mean "missing" / omit.
    """
    if token == "self":
        return current_principal.user_id
    if token in principals:
        return principals[token].user_id
    if token.startswith("static:"):
        return token.split(":", 1)[1]
    if token.startswith("env:"):
        var = token.split(":", 1)[1]
        return os.getenv(var)
    if token == "missing":
        return None
    return token


def render_path(path_template: str, placeholders: Dict[str, Optional[str]]) -> str:
    """
    Replace {placeholder} tokens. If a value is None => remove token:
      - If token is in path segment: replaced with empty -> may produce double slashes (normalized later)
      - If token appears in query string: user should provide template with explicit parameter; we will just replace.
    """
    out = path_template
    for k, v in placeholders.items():
        out = out.replace("{" + k + "}", "" if v is None else str(v))
    # normalize accidental double slashes (keep leading // in scheme only)
    out = re.sub(r"//+", "/", out)
    if not out.startswith("/"):
        out = "/" + out
    return out


# -----------------------------
# Suite runner
# -----------------------------
class SuiteRunner:
    def __init__(
        self,
        cfg: SuiteConfig,
        timeout_s: float,
        concurrency: int,
        retries: int,
        backoff_base: float,
        backoff_cap: float,
        transformer_plugin: Optional[str],
        outdir: Path,
        verbose: bool,
    ):
        self.cfg = cfg
        self.timeout_s = timeout_s
        self.sem = asyncio.Semaphore(max(1, concurrency))
        self.transformer_registry = build_transformer_registry(transformer_plugin)
        self.requester = AsyncRequester(
            timeout_s=timeout_s,
            retries=retries,
            backoff_base=backoff_base,
            backoff_cap=backoff_cap,
            insecure_tls=cfg.insecure_tls,
        )
        self.outdir = outdir
        self.verbose = verbose

    async def run(self) -> List[TestResult]:
        results: List[TestResult] = []
        tasks: List[asyncio.Task] = []

        limits = httpx.Limits(
            max_connections=1000,  # high ceiling; effective parallelism still bounded by semaphore
            max_keepalive_connections=200,
            keepalive_expiry=30.0,
        )

        async with httpx.AsyncClient(
            verify=not self.cfg.insecure_tls,
            follow_redirects=True,
            limits=limits,
            headers={"User-Agent": "Enterprise-QA-AuthZSuite/2.0"},
        ) as client:
            for target in self.cfg.targets:
                for case in self.cfg.cases:
                    tasks.extend(await self._case_tasks(client, target, case))

            # execute
            for coro in asyncio.as_completed(tasks):
                res = await coro
                results.append(res)

        return results

    async def _case_tasks(
        self,
        client: httpx.AsyncClient,
        target: str,
        case: TestCase,
    ) -> List[asyncio.Task]:
        tasks: List[asyncio.Task] = []

        # allow vector
        if case.allow:
            tasks.append(asyncio.create_task(self._run_expectation(client, target, case, case.allow, vector="allow")))

        # deny vectors
        for d in (case.deny or []):
            tasks.append(asyncio.create_task(self._run_expectation(client, target, case, d, vector="deny")))

        # extra vectors based on observed IDs (only if allow has resolvable ID(s))
        extra = case.extra_vectors or []
        if extra and case.allow:
            # use allow placeholders to derive an "observed id" per placeholder
            allow_pr = self.cfg.principals[case.allow.principal]
            observed: Dict[str, Optional[str]] = {}
            for ph in case.placeholders:
                token = case.allow.placeholder_values.get(ph, "self")
                observed[ph] = resolve_placeholder_value(token, ph, self.cfg.principals, allow_pr)

            # If we have any observed values, create extra vectors per placeholder (one-at-a-time)
            for ph, obs in observed.items():
                if not obs:
                    continue
                vectors = PayloadFactory.vectors_for_id(obs, enable_numeric_bva=case.enable_numeric_bva)
                for vname in extra:
                    if vname not in vectors:
                        continue
                    vval = vectors[vname]
                    # create a vector expectation that should be denied or rejected (deny_status)
                    # Some systems will return 400 for malformed; allow it via expected_status if provided.
                    exp_status = case.deny_status or self.cfg.defaults_deny_status
                    if vname in ("malformed", "numeric_bva_alpha"):
                        exp_status = sorted(set(exp_status + [400, 422]))
                    elif vname == "missing":
                        exp_status = sorted(set(exp_status + [400, 422]))
                    exp = CaseExpectation(
                        principal=case.allow.principal,
                        placeholder_values={**case.allow.placeholder_values, ph: "missing" if vval is None else f"static:{vval}"},
                        expected_status=exp_status,
                    )
                    tasks.append(asyncio.create_task(self._run_expectation(client, target, case, exp, vector=vname)))

        return tasks

    async def _run_expectation(
        self,
        client: httpx.AsyncClient,
        target: str,
        case: TestCase,
        exp: CaseExpectation,
        vector: str,
    ) -> TestResult:
        async with self.sem:
            pr = self.cfg.principals.get(exp.principal)
            if not pr:
                return TestResult(
                    target=target,
                    case=case.name,
                    vector=vector,
                    method=case.method,
                    url="",
                    principal=exp.principal,
                    expected_status=exp.expected_status or [],
                    actual_status=None,
                    ok=False,
                    latency_ms=0.0,
                    error=f"Unknown principal: {exp.principal}",
                )

            # Resolve placeholders
            rendered: Dict[str, Optional[str]] = {}
            for ph in case.placeholders:
                token = exp.placeholder_values.get(ph, "self")
                rendered[ph] = resolve_placeholder_value(token, ph, self.cfg.principals, pr)

            path = render_path(case.path_template, rendered)
            url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))

            # Compose headers
            headers = dict(case.headers or {})
            if pr.token:
                headers[self.cfg.auth_header] = pr.token

            json_body = case.json_body
            data_body = case.data_body

            # Expected statuses
            expected = exp.expected_status
            if expected is None:
                # infer by vector type
                if vector == "allow":
                    expected = case.allow_status or self.cfg.defaults_allow_status
                else:
                    expected = case.deny_status or self.cfg.defaults_deny_status

            # Apply optional transformation strategy (data-driven). This supports benign built-ins
            # and organization-approved strategies via --transformer-plugin.
            spec = RequestSpec(method=case.method, url=url, headers=headers, json_body=json_body, data_body=data_body)
            try:
                spec, used_strategies = apply_transformations(
                    spec=spec,
                    target=target,
                    case=case.name,
                    vector=vector,
                    principal=exp.principal,
                    strategy=exp.transformation_strategy,
                    strategy_args=exp.transformation_args,
                    registry=self.transformer_registry,
                )
            except RestrictedTransformationError as e:
                return TestResult(
                    target=target,
                    case=case.name,
                    vector=vector,
                    method=case.method,
                    url=url,
                    principal=exp.principal,
                    transformations=normalize_strategy_list(exp.transformation_strategy),
                    expected_status=expected,
                    actual_status=None,
                    ok=False,
                    latency_ms=0.0,
                    error=str(e),
                )

            # Use possibly transformed request spec
            url = spec.url
            headers = spec.headers
            json_body = spec.json_body
            data_body = spec.data_body

            status, latency_ms, resp_headers, resp_text, rid = await self.requester.request(
                client=client,
                method=case.method.upper(),
                url=url,
                headers=headers,
                json_body=json_body,
                data_body=data_body,
            )

            ok = (status in expected)
            leaked = None
            snippet = None
            if resp_text:
                snippet = safe_snippet(resp_text, 500)

            # Leak check: only meaningful on deny-ish vectors
            leaked_markers: List[str] = []
            markers = [m.lower() for m in (case.sensitive_markers or [])]
            if markers and vector != "allow" and resp_text:
                lower = resp_text.lower()
                for m in markers:
                    if m and m in lower:
                        leaked_markers.append(m)
                if leaked_markers:
                    ok = False

            if self.verbose:
                tag = f"{C.PASS}PASS{C.END}" if ok else f"{C.FAIL}FAIL{C.END}"
                print(f"[{tag}] {case.name} {vector} {case.method} {url} -> {status} (exp {expected}) {latency_ms:.1f}ms")

            return TestResult(
                target=target,
                case=case.name,
                vector=vector,
                method=case.method.upper(),
                url=url,
                principal=pr.name,
                transformations=used_strategies or None,
                expected_status=expected,
                actual_status=status,
                ok=ok,
                latency_ms=latency_ms,
                error=None if ok else None,
                request_id=rid,
                evidence_snippet=snippet if not ok else None,
                leaked_markers=leaked_markers or None,
            )


# -----------------------------
# Reporting (JSON + HTML)
# -----------------------------
def summarize(results: List[TestResult]) -> Dict[str, Any]:
    total = len(results)
    passed = sum(1 for r in results if r.ok)
    failed = total - passed

    by_target: Dict[str, Dict[str, int]] = {}
    for r in results:
        by_target.setdefault(r.target, {"passed": 0, "failed": 0, "total": 0})
        by_target[r.target]["total"] += 1
        if r.ok:
            by_target[r.target]["passed"] += 1
        else:
            by_target[r.target]["failed"] += 1

    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "by_target": by_target,
    }


def write_json(outdir: Path, suite_meta: Dict[str, Any], results: List[TestResult]) -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = outdir / f"security_regression_report_{stamp}.json"
    payload = {
        "meta": suite_meta,
        "summary": summarize(results),
        "results": [dataclasses.asdict(r) for r in results],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def write_html(outdir: Path, suite_meta: Dict[str, Any], results: List[TestResult]) -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = outdir / f"security_regression_report_{stamp}.html"

    summ = summarize(results)
    rows = []
    for r in results:
        cls = "ok" if r.ok else "bad"
        leaked = ", ".join(r.leaked_markers) if r.leaked_markers else ""
        rid = r.request_id or ""
        evidence = (r.evidence_snippet or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        rows.append(f"""
<tr class="{cls}">
  <td>{r.target}</td>
  <td>{r.case}</td>
  <td>{r.vector}</td>
  <td>{r.principal}</td>
  <td>{", ".join(r.transformations) if r.transformations else ""}</td>
  <td>{r.method}</td>
  <td><code>{r.url}</code></td>
  <td>{r.actual_status}</td>
  <td>{",".join(map(str, r.expected_status))}</td>
  <td>{r.latency_ms:.1f}</td>
  <td>{leaked}</td>
  <td><code>{rid}</code></td>
  <td><details><summary>show</summary><pre>{evidence}</pre></details></td>
</tr>
""")

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Security Regression Report</title>
<style>
body {{ font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial; margin: 20px; }}
h1 {{ margin: 0 0 8px 0; }}
.small {{ color: #555; }}
.kpis {{ display: flex; gap: 16px; margin: 12px 0 18px 0; }}
.kpi {{ padding: 10px 12px; border: 1px solid #ddd; border-radius: 10px; min-width: 160px; }}
.kpi b {{ font-size: 18px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th, td {{ border: 1px solid #e6e6e6; padding: 6px 8px; vertical-align: top; }}
th {{ background: #fafafa; position: sticky; top: 0; }}
tr.ok {{ background: #f4fff6; }}
tr.bad {{ background: #fff4f4; }}
code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; }}
details pre {{ white-space: pre-wrap; }}
</style>
</head>
<body>
<h1>Security Regression Report</h1>
<div class="small">Generated: {suite_meta.get("generated_at")} | Concurrency: {suite_meta.get("concurrency")} | Timeout: {suite_meta.get("timeout_s")}s</div>

<div class="kpis">
  <div class="kpi"><div>Total</div><b>{summ["total"]}</b></div>
  <div class="kpi"><div>Passed</div><b>{summ["passed"]}</b></div>
  <div class="kpi"><div>Failed</div><b>{summ["failed"]}</b></div>
</div>

<table>
<thead>
<tr>
  <th>Target</th><th>Case</th><th>Vector</th><th>Principal</th><th>Transforms</th><th>Method</th><th>URL</th>
  <th>Actual</th><th>Expected</th><th>Latency(ms)</th><th>Leaks</th><th>Request-ID</th><th>Evidence</th>
</tr>
</thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
</body>
</html>
"""
    path.write_text(html, encoding="utf-8")
    return path


# -----------------------------
# Config loading
# -----------------------------
def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _env_or_empty(name: str) -> str:
    return os.getenv(name, "")


def load_suite_config(
    config_path: Optional[Path],
    targets_csv: Optional[str],
    insecure_tls: bool,
) -> SuiteConfig:
    """
    Loads config from JSON file OR env-driven single-case mode.
    """
    if config_path:
        data = _read_json(config_path)

        targets = data.get("targets") or []
        if not isinstance(targets, list) or not targets:
            raise ValueError("Config must include non-empty 'targets' list")

        auth_header = data.get("auth_header") or "Authorization"

        principals_raw = data.get("principals") or {}
        principals: Dict[str, Principal] = {}
        for name, spec in principals_raw.items():
            token = _env_or_empty(spec.get("token_env", "")) if isinstance(spec, dict) else ""
            user_id = _env_or_empty(spec.get("id_env", "")) if isinstance(spec, dict) else ""
            principals[name] = Principal(name=name, token=token, user_id=user_id or None)

        defaults = data.get("defaults") or {}
        defaults_allow = defaults.get("allow_status") or [200]
        defaults_deny = defaults.get("deny_status") or [403, 404]

        cases_raw = data.get("cases") or []
        cases: List[TestCase] = []
        for c in cases_raw:
            allow_raw = c.get("allow")
            deny_raw = c.get("deny") or []
            allow = None
            if allow_raw:
                allow = CaseExpectation(
                    principal=allow_raw["principal"],
                    placeholder_values=allow_raw.get("placeholder_values") or {},
                    expected_status=allow_raw.get("expected_status"),
                    transformation_strategy=allow_raw.get("transformation_strategy"),
                    transformation_args=allow_raw.get("transformation_args"),
                )
            deny = []
            for d in deny_raw:
                deny.append(CaseExpectation(
                    principal=d["principal"],
                    placeholder_values=d.get("placeholder_values") or {},
                    expected_status=d.get("expected_status"),
                    transformation_strategy=d.get("transformation_strategy"),
                    transformation_args=d.get("transformation_args"),
                ))

            cases.append(TestCase(
                name=c["name"],
                method=c.get("method", "GET"),
                path_template=c["path_template"],
                placeholders=c.get("placeholders") or [],
                allow=allow,
                deny=deny or None,
                headers=c.get("headers"),
                json_body=c.get("json_body"),
                data_body=c.get("data_body"),
                allow_status=c.get("allow_status"),
                deny_status=c.get("deny_status"),
                sensitive_markers=c.get("sensitive_markers"),
                extra_vectors=c.get("extra_vectors"),
                enable_numeric_bva=bool(c.get("enable_numeric_bva", False)),
            ))

        return SuiteConfig(
            targets=[t.rstrip("/") for t in targets],
            auth_header=auth_header,
            principals=principals,
            cases=cases,
            defaults_allow_status=list(map(int, defaults_allow)),
            defaults_deny_status=list(map(int, defaults_deny)),
            insecure_tls=insecure_tls or bool(data.get("insecure_tls", False)),
        )

    # Env-driven single-case mode (minimal, quick)
    targets_env = targets_csv or os.getenv("TARGETS", "")
    targets = [t.strip().rstrip("/") for t in targets_env.split(",") if t.strip()]
    if not targets:
        raise ValueError("Provide targets via --targets or TARGETS env var (comma separated).")

    auth_header = os.getenv("AUTH_HEADER", "Authorization")

    user_a_token = os.getenv("USER_A_TOKEN", "")
    user_a_id = os.getenv("USER_A_ID", "") or None
    user_b_id = os.getenv("USER_B_ID", "") or None
    endpoint_template = os.getenv("ENDPOINT_TEMPLATE", "")

    if not endpoint_template:
        raise ValueError("ENDPOINT_TEMPLATE env var is required in env-driven mode.")

    principals = {
        "userA": Principal(name="userA", token=user_a_token, user_id=user_a_id),
        "userB": Principal(name="userB", token=os.getenv("USER_B_TOKEN", ""), user_id=user_b_id),
    }

    # statuses
    deny_status_raw = os.getenv("DENY_STATUS", "403,404")
    deny_status = [int(x.strip()) for x in deny_status_raw.split(",") if x.strip().isdigit()] or [403, 404]
    allow_status_raw = os.getenv("ALLOW_STATUS", "200")
    allow_status = [int(x.strip()) for x in allow_status_raw.split(",") if x.strip().isdigit()] or [200]

    # placeholders: infer from template braces if not provided
    placeholders = re.findall(r"\{([a-zA-Z0-9_]+)\}", endpoint_template)
    placeholders = placeholders or ["user_id"]

    # build case:
    case = TestCase(
        name="env_case",
        method=os.getenv("METHOD", "GET"),
        path_template=endpoint_template,
        placeholders=placeholders,
        allow=CaseExpectation(principal="userA", placeholder_values={placeholders[0]: "self"}, transformation_strategy=os.getenv("TRANSFORMATION_STRATEGY_ALLOW") or None),
        deny=[CaseExpectation(principal="userA", placeholder_values={placeholders[0]: "userB"}, transformation_strategy=os.getenv("TRANSFORMATION_STRATEGY_DENY") or None)] if user_b_id else [],
        allow_status=allow_status,
        deny_status=deny_status,
        sensitive_markers=[m.strip() for m in os.getenv("SENSITIVE_MARKERS", "").split(",") if m.strip()] or None,
        extra_vectors=[v.strip() for v in os.getenv("EXTRA_VECTORS", "malformed,missing,random").split(",") if v.strip()],
        enable_numeric_bva=(os.getenv("ENABLE_NUMERIC_BVA", "0") == "1"),
    )

    return SuiteConfig(
        targets=targets,
        auth_header=auth_header,
        principals=principals,
        cases=[case],
        defaults_allow_status=allow_status,
        defaults_deny_status=deny_status,
        insecure_tls=insecure_tls,
    )


# -----------------------------
# CLI
# -----------------------------
def parse_args(argv: List[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Enterprise async access-control regression suite (safe).")
    ap.add_argument("--config", type=str, default="", help="Path to JSON config (recommended).")
    ap.add_argument("--targets", type=str, default="", help="Comma-separated targets (env-driven mode).")
    ap.add_argument("--concurrency", type=int, default=200, help="Max in-flight requests.")
    ap.add_argument("--timeout", type=float, default=10.0, help="Request timeout seconds.")
    ap.add_argument("--retries", type=int, default=2, help="Retries for transient failures (5xx/429/timeouts).")
    ap.add_argument("--backoff-base", type=float, default=0.25, help="Exponential backoff base seconds.")
    ap.add_argument("--backoff-cap", type=float, default=4.0, help="Exponential backoff cap seconds.")
    ap.add_argument("--insecure-tls", action="store_true", help="Disable TLS verification (internal env only).")
    ap.add_argument("--outdir", type=str, default="./security_reports", help="Directory for JSON/HTML reports.")
    ap.add_argument("--no-html", action="store_true", help="Disable HTML report generation.")
    ap.add_argument("-v", "--verbose", action="store_true", help="Verbose per-request output.")
    ap.add_argument("--transformer-plugin", type=str, default="", help="Path to transformer plugin (.py file or module).")
    ap.add_argument("--run", action="store_true", help="Run suite (otherwise prints config tips).")
    return ap.parse_args(argv)


def validate_suite_config(cfg: SuiteConfig) -> None:
    # Validate targets
    for t in cfg.targets:
        p = urlparse(t)
        if not p.scheme or not p.netloc:
            raise ValueError(f"Invalid target URL: {t}")

    # Validate principals
    if not cfg.principals:
        raise ValueError("No principals defined.")
    if cfg.auth_header.strip() == "":
        raise ValueError("auth_header cannot be empty.")

    # Validate cases
    if not cfg.cases:
        raise ValueError("No cases defined.")
    for c in cfg.cases:
        if not c.path_template:
            raise ValueError(f"Case '{c.name}' missing path_template")
        if not c.placeholders:
            # allow placeholder-less paths
            pass
        if c.allow and c.allow.principal not in cfg.principals:
            raise ValueError(f"Case '{c.name}' allow principal unknown: {c.allow.principal}")
        for d in (c.deny or []):
            if d.principal not in cfg.principals:
                raise ValueError(f"Case '{c.name}' deny principal unknown: {d.principal}")

        # Validate transformation strategy shapes (actual implementation may come from plugin)
        exps: List[CaseExpectation] = []
        if c.allow:
            exps.append(c.allow)
        exps.extend(c.deny or [])
        for e in exps:
            st = e.transformation_strategy
            if st is None:
                pass
            elif isinstance(st, str):
                if not st.strip():
                    raise ValueError(f"Case '{c.name}' has empty transformation_strategy")
            elif isinstance(st, list):
                if not all(isinstance(x, str) and x.strip() for x in st):
                    raise ValueError(f"Case '{c.name}' has invalid transformation_strategy list")
            else:
                raise ValueError(f"Case '{c.name}' transformation_strategy must be str or list[str]")

            if e.transformation_args is not None and not isinstance(e.transformation_args, dict):
                raise ValueError(f"Case '{c.name}' transformation_args must be an object/dict")


def print_config_hint() -> None:
    print(f"{C.INFO}Tip:{C.END} Use --config ac_suite.json for enterprise runs, or env-driven mode for quick checks.")
    print("Env-driven minimum:")
    print("  TARGETS, USER_A_TOKEN, USER_A_ID, USER_B_ID, ENDPOINT_TEMPLATE")


async def async_main(argv: List[str]) -> int:
    args = parse_args(argv)

    if not args.run:
        print_config_hint()
        return 0

    cfg = load_suite_config(
        config_path=Path(args.config) if args.config else None,
        targets_csv=args.targets if args.targets else None,
        insecure_tls=args.insecure_tls,
    )
    validate_suite_config(cfg)

    outdir = Path(args.outdir)
    runner = SuiteRunner(
        cfg=cfg,
        timeout_s=args.timeout,
        concurrency=args.concurrency,
        retries=args.retries,
        backoff_base=args.backoff_base,
        backoff_cap=args.backoff_cap,
        transformer_plugin=args.transformer_plugin or None,
        outdir=outdir,
        verbose=args.verbose,
    )

    print(f"\n{C.BOLD}=== Enterprise AuthZ Regression Suite (Async) ==={C.END}")
    print(f"Generated at : {utc_iso()}")
    print(f"Targets      : {len(cfg.targets)}")
    print(f"Cases        : {len(cfg.cases)}")
    print(f"Concurrency  : {args.concurrency}")
    print(f"Timeout      : {args.timeout}s | Retries={args.retries} | Backoff={args.backoff_base}-{args.backoff_cap}s")
    print(f"TLS Verify   : {'OFF' if cfg.insecure_tls else 'ON'}")
    print("===============================================\n")

    t0 = time.perf_counter()
    results = await runner.run()
    runtime_s = time.perf_counter() - t0

    suite_meta = {
        "generated_at": utc_iso(),
        "runtime_s": runtime_s,
        "concurrency": args.concurrency,
        "timeout_s": args.timeout,
        "retries": args.retries,
        "backoff_base": args.backoff_base,
        "backoff_cap": args.backoff_cap,
        "transformer_plugin": args.transformer_plugin or None,
        "transformers_available": sorted(runner.transformer_registry.keys()),
        "targets": cfg.targets,
        "cases": [c.name for c in cfg.cases],
    }

    json_path = write_json(outdir, suite_meta, results)
    html_path = None if args.no_html else write_html(outdir, suite_meta, results)

    summ = summarize(results)
    fail = summ["failed"]

    print(f"{C.BOLD}=== Summary ==={C.END}")
    print(f"Total: {summ['total']} | Passed: {summ['passed']} | Failed: {summ['failed']} | Runtime: {runtime_s:.2f}s")
    for tgt, s in summ["by_target"].items():
        print(f"- {tgt}: total={s['total']} passed={s['passed']} failed={s['failed']}")
    print(f"\nJSON report: {json_path}")
    if html_path:
        print(f"HTML report: {html_path}")

    # CI exit codes:
    # 0 success, 2 test failures, 1 runtime/config errors
    return 0 if fail == 0 else 2


def main() -> None:
    try:
        code = asyncio.run(async_main(sys.argv[1:]))
        raise SystemExit(code)
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as e:
        print(f"{C.FAIL}ERROR:{C.END} {e}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
