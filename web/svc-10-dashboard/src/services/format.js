// pg unwraps a pgtype-shaped JSON value (e.g. {"Valid":true,"Int32":70}) into a
// plain scalar or null. sqlc emits nullable columns in this shape; the UI uses
// this so components can treat fields as plain values.
export function pg(v) {
  if (v && typeof v === "object" && "Valid" in v) {
    if (!v.Valid) return null;
    for (const k of ["String", "Int32", "Int64", "Float64", "Bool", "Time"]) {
      if (k in v) return v[k];
    }
    return null;
  }
  return v;
}

// verdictClass maps a verdict label to a CSS badge class.
export function verdictClass(label) {
  switch (label) {
    case "phishing":
    case "malware":
      return "badge badge-danger";
    case "suspicious":
      return "badge badge-warn";
    case "benign":
    case "legitimate":
      return "badge badge-ok";
    default:
      return "badge";
  }
}
