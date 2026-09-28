import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

random.seed(42)
np.random.seed(42)

USERS = [f"user{i:03d}" for i in range(1, 31)]
COUNTRIES = ["JP", "US", "CN", "DE", "BR", "IN"]
EVENT_TYPES = ["login", "file_access", "permission_change", "data_export"]

def random_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"

def normal_logs(n=800, start=datetime(2026, 9, 1, 8, 0)):
    rows = []
    for _ in range(n):
        t = start + timedelta(minutes=random.randint(0, 60*24*20))
        t = t.replace(hour=random.randint(9, 19))
        rows.append({
            "timestamp": t,
            "user": random.choice(USERS),
            "source_ip": random_ip(),
            "country": "JP",
            "event_type": random.choice(["login", "file_access"]),
            "status": "success",
        })
    return rows

def inject_brute_force(rows, user="user007", n_fail=8):
    base = datetime(2026, 9, 10, 3, 0)
    ip = random_ip()
    for i in range(n_fail):
        rows.append({"timestamp": base + timedelta(seconds=i*20), "user": user,
                     "source_ip": ip, "country": "CN", "event_type": "login", "status": "failed"})
    rows.append({"timestamp": base + timedelta(seconds=n_fail*20+5), "user": user,
                 "source_ip": ip, "country": "CN", "event_type": "login", "status": "success"})
    return rows

def inject_impossible_travel(rows, user="user012"):
    t0 = datetime(2026, 9, 12, 10, 0)
    rows.append({"timestamp": t0, "user": user, "source_ip": random_ip(),
                 "country": "JP", "event_type": "login", "status": "success"})
    rows.append({"timestamp": t0 + timedelta(minutes=15), "user": user, "source_ip": random_ip(),
                 "country": "US", "event_type": "login", "status": "success"})
    return rows

def inject_privilege_escalation(rows, user="user020"):
    t0 = datetime(2026, 9, 14, 23, 30)
    rows.append({"timestamp": t0, "user": user, "source_ip": random_ip(),
                 "country": "JP", "event_type": "permission_change", "status": "success"})
    rows.append({"timestamp": t0 + timedelta(minutes=5), "user": user, "source_ip": random_ip(),
                 "country": "JP", "event_type": "data_export", "status": "success"})
    return rows

def inject_ip_scan(rows, ip=None):
    ip = ip or random_ip()
    t0 = datetime(2026, 9, 16, 4, 0)
    for i in range(15):
        rows.append({"timestamp": t0 + timedelta(seconds=i*10), "user": random.choice(USERS),
                     "source_ip": ip, "country": "DE", "event_type": "login", "status": "failed"})
    return rows

def build_dataset():
    rows = normal_logs()
    rows = inject_brute_force(rows)
    rows = inject_impossible_travel(rows)
    rows = inject_privilege_escalation(rows)
    rows = inject_ip_scan(rows)
    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    return df
