"""Read-only X endpoint feasibility; never notarization, proof or passport issuance.

Only the prospective owner's process may handle this module's private inputs.
Public results contain fixed status/schema flags and byte counts, never headers,
account IDs, names, follower counts, response bodies or exception messages.
"""
import http.client
import json
import re
import ssl
from urllib.parse import urlencode

MAX_REQUEST_BYTES = 16 * 1024
MAX_BODY_BYTES = 32 * 1024
MAX_HEADER_BYTES = 16 * 1024
MAX_JSON_DEPTH = 32
TIMEOUT_SECONDS = 15
# Pinned from X's public startup-DfleHLPI.js, SHA256
# c3c8baef5fbc8e979b4add3b6f578b8d4d34a9f3dcf0972fd53c1b5a067b3a45.
# viewer_v2(safety_level:"UserSelfViewOnly"); no caller-selected account ID.
VIEWER_QUERY_ID = "ZXYoRV2xxqxwt4hUF3IzQg"
VIEWER_VARIABLES = {"__relay_internal__pv__xclientsfeaturesappviewerisloggedinrelayprovider": True}
TARGET = "/graphql/" + VIEWER_QUERY_ID + "/viewerQuery?" + urlencode({
    "variables": json.dumps(VIEWER_VARIABLES, separators=(",", ":"))})
ENDPOINTS = {"browser-viewer-v2": ("api.x.com", TARGET)}
PROFILE = "nockapp-x-viewer-feasibility-v2"


class ProbeRejected(ValueError):
    """A fixed public error code; never include supplied text in exceptions."""


def reject(code):
    raise ProbeRejected(code)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            reject("ambiguous-json")
        result[key] = value
    return result


def strict_response_json(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_BODY_BYTES:
        reject("response-size")
    # Bound recursion before the standard JSON decoder allocates a nested tree.
    depth = 0
    quoted = escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > MAX_JSON_DEPTH:
                reject("response-depth")
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                reject("response-json")
    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(text, object_pairs_hook=unique_object,
                          parse_constant=lambda _: reject("response-json"))
    except ProbeRejected:
        raise
    except (ValueError, RecursionError, UnicodeError):
        reject("response-json")


def inspect_current_user(raw, schema="v1"):
    """Validate a candidate schema privately; this function authenticates nothing.

    v1's id_str and followers_count must belong to its ROOT current-user object.
    The documented v2 /users/me alternative takes both from the same data object.
    Public-profile objects are not distinguished by JSON alone: the independently
    approved endpoint/authentication semantics and notarization are still required.
    """
    obj = strict_response_json(raw)
    if type(obj) is not dict or obj.get("error") or (schema != "viewer-v2" and obj.get("errors")):
        reject("response-schema")
    if schema == "v1":
        subject, metrics = obj, obj
        identifier = subject.get("id_str")
    elif schema == "v2":
        subject = obj.get("data")
        if type(subject) is not dict:
            reject("response-schema")
        metrics = subject.get("public_metrics")
        identifier = subject.get("id")
    elif schema == "viewer-v2":
        # The pinned self-view query is the source semantic boundary. JSON
        # shape alone cannot distinguish a current-user query from a lookup.
        errors = obj.get("errors")
        if errors is not None and (type(errors) is not list or errors):
            reject("source-query-error")
        data = obj.get("data")
        viewer = data.get("viewer") if type(data) is dict else None
        results = viewer.get("user_results") if type(viewer) is dict else None
        subject = results.get("result") if type(results) is dict else None
        if type(subject) is not dict or subject.get("__typename") != "User":
            reject("current-user-unavailable")
        identifier = subject.get("rest_id")
        metrics = subject.get("relationship_counts")
    else:
        reject("unsupported-schema")
    if (type(identifier) is not str or re.fullmatch(r"[1-9][0-9]{0,19}", identifier) is None
            or int(identifier) > 2**64 - 1):
        reject("account-id-format")
    if schema == "v1" and "id" in subject:
        if type(subject["id"]) is not int or subject["id"] != int(identifier):
            reject("account-id-mismatch")
    if type(metrics) is not dict:
        reject("response-schema")
    count = metrics.get("followers" if schema == "viewer-v2" else "followers_count")
    if type(count) is not int or not 0 <= count <= 2**32 - 1:
        reject("follower-count-format")
    return {"stable_account_id_present": True, "same_object_follower_count_present": True}


def private_headers(context):
    if type(context) is not dict or set(context) != {"cookie", "csrf", "authorization"}:
        reject("request-schema")
    for value in context.values():
        if (type(value) is not str or not value or len(value) > MAX_REQUEST_BYTES
                or any(ord(c) < 32 or ord(c) > 126 for c in value)):
            reject("request-header-format")
    if not context["authorization"].startswith("Bearer ") or len(context["authorization"]) <= 7:
        reject("request-authorization")
    # Keep only the two session cookies required by the browser candidate.
    # Cookie content is never used as evidence of an account ID or owner.
    cookies = {}
    for piece in context["cookie"].split(";"):
        key, sep, value = piece.strip().partition("=")
        if key in ("auth_token", "ct0"):
            if key in cookies or not sep or not value:
                reject("request-cookie-format")
            cookies[key] = value
    if set(cookies) != {"auth_token", "ct0"} or cookies["ct0"] != context["csrf"]:
        reject("request-session-context")
    headers = {
        "Cookie": "; ".join(key + "=" + cookies[key] for key in ("auth_token", "ct0")),
        "X-Csrf-Token": context["csrf"], "Authorization": context["authorization"],
        "Accept": "application/json", "Accept-Encoding": "identity", "Connection": "close",
        "Content-Type": "application/json", "Origin": "https://x.com", "Referer": "https://x.com/",
        "X-Twitter-Auth-Type": "OAuth2Session", "X-Twitter-Active-User": "yes",
    }
    if sum(len(k) + len(v) + 4 for k, v in headers.items()) + len(TARGET) + 100 > MAX_REQUEST_BYTES:
        reject("request-size")
    return headers


def read_response(response):
    """Bound framing before reading private bytes. Never return raw headers."""
    headers = response.getheaders()
    if sum(len(k) + len(v) + 4 for k, v in headers) > MAX_HEADER_BYTES:
        reject("response-headers-size")
    framing = {}
    for key, value in headers:
        name = key.lower()
        if name in ("content-length", "transfer-encoding", "content-encoding", "content-type"):
            if name in framing:
                reject("response-framing")
            framing[name] = value.strip()
    length = framing.get("content-length")
    transfer = framing.get("transfer-encoding")
    if length is not None and transfer is not None:
        reject("response-framing")
    if length is not None:
        if re.fullmatch(r"0|[1-9][0-9]*", length) is None or len(length) > 8:
            reject("response-framing")
        if int(length) > MAX_BODY_BYTES:
            reject("response-size")
    elif transfer != "chunked":
        reject("unsupported-response-framing")
    if framing.get("content-encoding", "identity").lower() != "identity":
        reject("unsupported-response-encoding")
    if framing.get("content-type", "").split(";", 1)[0].lower() != "application/json":
        reject("response-content-type")
    raw = response.read(MAX_BODY_BYTES + 1)
    if len(raw) > MAX_BODY_BYTES or (length is not None and len(raw) != int(length)):
        reject("response-size")
    return raw


def probe(endpoint, context):
    """One explicitly selected current-user GET, no redirects/retries or persistence.

    This is preliminary ordinary TLS. Even a successful shape test is explicitly
    unverified and must never authorize a credential or a production source policy.
    """
    result = {"profile": PROFILE, "notarized": False, "verified": False,
              "passport_issuance_allowed": False, "account_control_established": False}
    connection = None
    try:
        if type(endpoint) is not str or endpoint not in ENDPOINTS:
            reject("unsupported-endpoint")
        headers = private_headers(context)
        host, target = ENDPOINTS[endpoint]
        # Construct explicitly: create_default_context can honor SSLKEYLOGFILE.
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        tls.load_default_certs()
        tls.minimum_version = tls.maximum_version = ssl.TLSVersion.TLSv1_2
        connection = http.client.HTTPSConnection(host, timeout=TIMEOUT_SECONDS, context=tls)
        connection.request("GET", target, headers=headers)
        response = connection.getresponse()
        result["http_status"] = response.status
        if response.status != 200:
            # Do not read or report private error bodies or sensitive headers.
            code = {401: "login-expired", 403: "endpoint-forbidden", 429: "rate-limited"}.get(
                response.status, "unsupported-http-status")
            reject(code)
        raw = read_response(response)
        result.update(inspect_current_user(raw, "viewer-v2"), response_body_bytes=len(raw), status="candidate-schema-observed")
    except ProbeRejected as error:
        result.update(status="rejected", code=error.args[0])
    except (OSError, ssl.SSLError, http.client.HTTPException):
        result.update(status="unavailable", code="source-connection-failed")
    finally:
        if connection is not None:
            connection.close()
    return result
