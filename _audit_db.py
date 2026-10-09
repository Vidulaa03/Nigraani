import sqlite3
from pathlib import Path

p = Path(__file__).resolve().parent / "demo.db"
print("exists", p.exists(), "size", p.stat().st_size if p.exists() else 0)
c = sqlite3.connect(p)
print("tables:")
for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
    print(" ", r[0])
for t in ["security_events", "detections", "decisions", "users", "orders"]:
    try:
        n = c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        cols = [x[1] for x in c.execute(f"PRAGMA table_info({t})")]
        print(t, "count=", n, "cols=", cols)
    except Exception as e:
        print(t, "ERR", e)
print("--- detections ---")
for r in c.execute("SELECT * FROM detections LIMIT 3"):
    print(r)
print("--- decisions ---")
for r in c.execute("SELECT * FROM decisions LIMIT 5"):
    print(r)
print("--- events ---")
for r in c.execute("SELECT * FROM security_events LIMIT 2"):
    print(r)
print("sim_labels", list(c.execute("SELECT sim_label, COUNT(*) FROM security_events GROUP BY sim_label")))
print("ips", list(c.execute("SELECT ip, COUNT(*) FROM security_events GROUP BY ip")))
print("methods", list(c.execute("SELECT method, COUNT(*) FROM security_events GROUP BY method")))
print("status", list(c.execute("SELECT status_code, COUNT(*) FROM security_events GROUP BY status_code")))
