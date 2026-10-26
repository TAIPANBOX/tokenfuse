"""Throwaway: apply one named mutant of the #478 fix to the broker, for one CI job."""
import sys

P = "crates/gateway/src/mcpbroker.rs"
MUTANTS = {
    "none": [],
    # The early refusal never fires.
    "M1": [("if let Some(why) = unjudgeable(&req) {",
            "if let Some(why) = unjudgeable(&req).filter(|_| false) {")],
    # A batch is let through.
    "M2": [("Value::Array(_) => Some(BATCH_RPC_MESSAGE),",
            "Value::Array(_) => Some(BATCH_RPC_MESSAGE).filter(|_| false),")],
    # Only a null method is refused, not any non-string one.
    "M3": [("Some(method) if !method.is_string() => Some(METHOD_RPC_MESSAGE),",
            "Some(method) if method.is_null() => Some(METHOD_RPC_MESSAGE),")],
    # A bare string, number or null is let through.
    "M4": [("_ => Some(NOT_AN_OBJECT_RPC_MESSAGE),",
            "_ => Some(NOT_AN_OBJECT_RPC_MESSAGE).filter(|_| false),")],
    # Overeager: an object with no method (a JSON-RPC response) is refused too.
    "M5": [("            _ => None,\n        },\n        Value::Array(_)",
            "            None => Some(METHOD_RPC_MESSAGE),\n            _ => None,\n        },\n        Value::Array(_)")],
    # The refusal answers HTTP 200 instead of 400.
    "M6": [("            notification: false,\n            status: Some(axum::http::StatusCode::BAD_REQUEST),",
            "            notification: false,\n            status: None,")],
    # The refusal carries the wrong JSON-RPC code.
    "M7": [("const INVALID_REQUEST_RPC_CODE: i64 = -32600;",
            "const INVALID_REQUEST_RPC_CODE: i64 = -32000;")],
}

name = sys.argv[1]
s = open(P).read()
for a, b in MUTANTS[name]:
    if s.count(a) != 1:
        sys.exit(f"{name}: the mutation site is not unique or is missing: {a!r}")
    s = s.replace(a, b)
open(P, "w").write(s)
print(f"{name}: applied {len(MUTANTS[name])} edit(s)")
