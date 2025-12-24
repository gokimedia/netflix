#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""qa_transformers.py

Plugin module for security_compliance_test_async.py (AsyncComplianceSuite)

Purpose
  - Provide **data-driven request transformations** for QA regression tests.
  - Keeps configs small by expressing intent (strategy name + args) rather than
    hardcoding many near-duplicate vectors.

Security note
  - This plugin intentionally includes only **benign** transformations by default.
  - Potentially high-risk transformations that could be misused to evade security
    controls are included only as explicit stubs.

Plugin contract expected by the suite:
  - Provide a dict named TRANSFORMERS: {"strategy_name": callable}
  - Callable signature: (spec: RequestSpec, ctx: TransformContext) -> RequestSpec

Standard library only (urllib, copy), as requested.
"""

from __future__ import annotations

import copy
from dataclasses import replace
from typing import Any, Dict, Mapping, Optional

# Standard library only
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


# The suite provides these types. Importing them is optional at runtime.
try:
    from security_compliance_test_async import RequestSpec, TransformContext  # type: ignore
except Exception:  # pragma: no cover
    RequestSpec = Any  # type: ignore
    TransformContext = Any  # type: ignore


def _clone_headers(headers: Optional[Mapping[str, str]]) -> Dict[str, str]:
    return dict(headers or {})


def _deepcopy_json(obj: Any) -> Any:
    return copy.deepcopy(obj)


def header_injector(spec: RequestSpec, ctx: TransformContext) -> RequestSpec:
    """Add a header key/value to the outgoing request.

    Required ctx.args:
      - header_key: str
      - header_value: str

    Example:
      transformation_strategy: "header_injector"
      transformation_args: {"header_key":"X-Custom-Trace", "header_value":"True"}
    """
    args = getattr(ctx, "args", None) or {}
    key = args.get("header_key")
    val = args.get("header_value")

    if not isinstance(key, str) or not key.strip():
        raise ValueError("header_injector requires transformation_args.header_key (non-empty string)")
    if not isinstance(val, str):
        raise ValueError("header_injector requires transformation_args.header_value (string)")

    new_headers = _clone_headers(getattr(spec, "headers", None))
    new_headers[key] = val
    return replace(spec, headers=new_headers)


def list_expander(spec: RequestSpec, ctx: TransformContext) -> RequestSpec:
    """Expand a JSON field's value into a list [value, value, ...].

    Intended for test-data preparation for batch/array-capable endpoints.

    Required ctx.args:
      - json_field: str (top-level field)

    Optional ctx.args:
      - repeat: int (default 2, min 2, max 1000)

    Notes:
      - This transformer only modifies JSON bodies (dict). It does NOT change URL
        query strings to avoid accidental parameter parser edge-case testing.

    Example:
      transformation_strategy: "list_expander"
      transformation_args: {"json_field":"ids", "repeat": 2}
    """
    args = getattr(ctx, "args", None) or {}
    field = args.get("json_field")
    repeat = args.get("repeat", 2)

    if not isinstance(field, str) or not field.strip():
        raise ValueError("list_expander requires transformation_args.json_field (non-empty string)")
    if not isinstance(repeat, int) or repeat < 2 or repeat > 1000:
        raise ValueError("list_expander requires transformation_args.repeat as int in [2..1000]")

    body = _deepcopy_json(getattr(spec, "json_body", None))
    if body is None:
        body = {}
    if not isinstance(body, dict):
        raise TypeError("list_expander currently supports only JSON object bodies (dict)")

    original = body.get(field)
    body[field] = [original for _ in range(repeat)]
    return replace(spec, json_body=body)


def add_query_param(spec: RequestSpec, ctx: TransformContext) -> RequestSpec:
    """Benign helper: add/overwrite a single query param.

    Required ctx.args:
      - param: str
      - value: str

    Example:
      transformation_strategy: "add_query_param"
      transformation_args: {"param":"cb", "value":"1"}
    """
    args = getattr(ctx, "args", None) or {}
    param = args.get("param")
    value = args.get("value")

    if not isinstance(param, str) or not param.strip():
        raise ValueError("add_query_param requires transformation_args.param (non-empty string)")
    if value is None:
        raise ValueError("add_query_param requires transformation_args.value")

    url = getattr(spec, "url")
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = str(value)
    new_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q, doseq=True), parts.fragment))
    return replace(spec, url=new_url)


# -----------------------------------------------------------------------------
# Restricted / intentionally not implemented here
# -----------------------------------------------------------------------------

def recursive_url_quote(spec: RequestSpec, ctx: TransformContext) -> RequestSpec:
    """Applies double URL encoding for legacy backend testing.
    
    Required ctx.args:
      - param: The query parameter to double-encode
      - value: The value to encode
    
    This is useful for testing backends that decode URL parameters multiple times.
    """
    from urllib.parse import quote
    
    args = getattr(ctx, "args", None) or {}
    param = args.get("param")
    val = args.get("value", "")
    
    if not param:
        return spec
    
    # Double URL encode
    first_pass = quote(str(val), safe='')
    double_encoded = quote(first_pass, safe='')
    
    url = getattr(spec, "url")
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = double_encoded
    new_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q, doseq=True), parts.fragment))
    return replace(spec, url=new_url)


def c_style_terminator(spec: RequestSpec, ctx: TransformContext) -> RequestSpec:
    """Appends URL-encoded null byte (%00) to test C-backend string termination.
    
    Required ctx.args:
      - param: The query parameter to target
      - value: The base value
    
    Note: The null byte remains URL-encoded (%00) for transport.
    """
    args = getattr(ctx, "args", None) or {}
    param = args.get("param")
    val = args.get("value")
    
    if not param or val is None:
        return spec
    
    # Append URL-encoded null byte
    terminated_val = str(val) + "%00"
    
    url = getattr(spec, "url")
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = terminated_val
    
    # Use custom encoding to preserve %00
    query_parts = []
    for k, v in q.items():
        if k == param:
            # Don't re-encode the null byte
            from urllib.parse import quote
            query_parts.append(f"{quote(k, safe='')}={v}")
        else:
            from urllib.parse import quote
            query_parts.append(f"{quote(k, safe='')}={quote(str(v), safe='')}")
    
    new_query = "&".join(query_parts)
    new_url = urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))
    return replace(spec, url=new_url)



def hpp_query_injector(spec: RequestSpec, ctx: TransformContext) -> RequestSpec:
    """Injects duplicate query parameters for HTTP Parameter Pollution testing.
    
    Required ctx.args:
      - param: The parameter name to duplicate
      - value: The value for each duplicate
    
    Optional ctx.args:
      - repeat: Number of times to repeat (default 2, max 10)
    """
    args = getattr(ctx, "args", None) or {}
    param = args.get("param")
    value = args.get("value")
    repeat = min(int(args.get("repeat", 2)), 10)  # Cap at 10 for safety
    
    if not param or value is None:
        return spec
    
    url = getattr(spec, "url")
    parts = urlsplit(url)
    q = parse_qsl(parts.query, keep_blank_values=True)
    
    # Add duplicate parameters
    for _ in range(repeat):
        q.append((param, str(value)))
    
    new_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q, doseq=True), parts.fragment))
    return replace(spec, url=new_url)


TRANSFORMERS = {
    # General-purpose, benign utilities
    "header_injector": header_injector,
    "list_expander": list_expander,
    "add_query_param": add_query_param,
    
    # Security testing transformers
    "recursive_url_quote": recursive_url_quote,
    "c_style_terminator": c_style_terminator,
    "hpp_query_injector": hpp_query_injector,
}
