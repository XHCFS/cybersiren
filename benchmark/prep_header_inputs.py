"""
Prep for the REAL svc-04 header harness:
  1. parse db/seeds/header_rules_demo_seed.sql -> _header_rules.json (id, target, score_impact, logic)
  2. build _header_inputs.jsonl from the representative CSV's svc-02-parsed fields
     (one AnalysisHeadersMessage-shaped record per email).
"""
import csv, json, re, sys
csv.field_size_limit(10**7)

# ---- 1. rules ----
sql = open("db/seeds/header_rules_demo_seed.sql").read()
# each tuple: (NULL, 'name', 'desc', 'ver', 'status', 'target', SCORE, '{json}'::jsonb)
rules = []
rid = 0
# capture score_impact + the (brace-balanced) logic jsonb blob; anchor the close on '::jsonb
for m in re.finditer(r"'(\w+)',\s*(-?\d+),\s*'(\{[\s\S]*?\})'::jsonb", sql):
    target, score, logic = m.group(1), int(m.group(2)), m.group(3)
    try:
        parsed = json.loads(logic)
    except Exception as e:
        print("skip (bad json):", target, score, str(e)[:60], file=sys.stderr); continue
    rid += 1
    rules.append({"id": rid, "target": target, "score_impact": score, "logic": parsed})
json.dump(rules, open("benchmark/_header_rules.json", "w"))
print(f"rules parsed: {len(rules)}")
cats = {}
for r in rules:
    c = r["logic"].get("category", "?"); cats[c] = cats.get(c, 0) + 1
print("by category:", cats)

# ---- 2. inputs ----
def norm(v): return "" if v is None else str(v).strip()
n = 0
with open("benchmark/cybersiren_e2e_benchmark_representative.csv", newline="") as f, \
     open("benchmark/_header_inputs.jsonl", "w") as out:
    for r in csv.DictReader(f):
        if r.get("has_headers", "0") != "1":
            # no headers -> header channel absent (exactly as production)
            out.write(json.dumps({"id": r["id"], "present": False}) + "\n"); n += 1; continue
        try:
            hops = int(float(r.get("received_hops") or 0))
        except ValueError:
            hops = 0
        msg = {
            "email_id": r["id"], "org_id": 1,
            "sender_email": norm(r.get("from_addr")),
            "sender_domain": norm(r.get("from_domain")),
            "sender_name": norm(r.get("from_display")),
            "reply_to_email": norm(r.get("reply_to")),
            "return_path": norm(r.get("return_path")),
            "auth_spf": norm(r.get("spf")),
            "auth_dkim": norm(r.get("dkim")),
            "auth_dmarc": norm(r.get("dmarc")),
            "hop_count": hops,
            "body_plain": norm(r.get("body_plain"))[:4000],
            "body_html": norm(r.get("body_html"))[:4000],
        }
        out.write(json.dumps({"id": r["id"], "present": True, "msg": msg}) + "\n"); n += 1
print(f"inputs written: {n}")
