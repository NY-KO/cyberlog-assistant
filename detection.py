import pandas as pd

def detect_brute_force(df, window_minutes=5, fail_threshold=5):
    df = df.sort_values("timestamp")
    alerts = []
    for user, g in df[df.event_type == "login"].groupby("user"):
        g = g.set_index("timestamp")
        fails = g[g.status == "failed"]
        if fails.empty:
            continue
        rolled = fails["status"].rolling(f"{window_minutes}min").count()
        if (rolled >= fail_threshold).any():
            alerts.append({"rule": "brute_force", "user": user,
                            "detail": f"{int(rolled.max())} failed logins within {window_minutes}min"})
    return alerts

def detect_impossible_travel(df, max_minutes=60):
    alerts = []
    for user, g in df[(df.event_type == "login") & (df.status == "success")].groupby("user"):
        g = g.sort_values("timestamp")
        prev = None
        for _, row in g.iterrows():
            if prev is not None and row["country"] != prev["country"]:
                gap = (row["timestamp"] - prev["timestamp"]).total_seconds() / 60
                if gap <= max_minutes:
                    alerts.append({"rule": "impossible_travel", "user": user,
                                    "detail": f"{prev['country']}→{row['country']} in {gap:.0f} min"})
            prev = row
    return alerts

def detect_unusual_hours(df, normal_range=(7, 21)):
    df = df.copy()
    df["hour"] = df["timestamp"].dt.hour
    odd = df[(df.hour < normal_range[0]) | (df.hour > normal_range[1])]
    return [{"rule": "unusual_hours", "user": r.user,
             "detail": f"activity at {r.timestamp.strftime('%H:%M')}"} for r in odd.itertuples()]

def detect_ip_broad_access(df, window_minutes=5, target_threshold=10):
    alerts = []
    window = pd.Timedelta(minutes=window_minutes)
    for ip, g in df.groupby("source_ip"):
        g = g.sort_values("timestamp").reset_index(drop=True)
        times = g["timestamp"].values
        users = g["user"].values
        max_count = 0
        for i in range(len(g)):
            window_start = times[i] - window.to_timedelta64()
            mask = (times <= times[i]) & (times >= window_start)
            distinct = len(set(users[mask]))
            if distinct > max_count:
                max_count = distinct
        if max_count >= target_threshold:
            alerts.append({"rule": "ip_broad_access", "user": ip,
                            "detail": f"{max_count} distinct users targeted within {window_minutes}min"})
    return alerts

def detect_privilege_escalation(df, follow_minutes=15):
    alerts = []
    perm = df[df.event_type == "permission_change"]
    for _, row in perm.iterrows():
        after = df[(df.user == row.user) & (df.timestamp > row.timestamp) &
                   (df.timestamp <= row.timestamp + pd.Timedelta(minutes=follow_minutes)) &
                   (df.event_type == "data_export")]
        if not after.empty:
            alerts.append({"rule": "privilege_escalation", "user": row.user,
                            "detail": "permission_change followed by data_export"})
    return alerts

def run_all_detections(df):
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    alerts = []
    alerts += detect_brute_force(df)
    alerts += detect_impossible_travel(df)
    alerts += detect_unusual_hours(df)
    alerts += detect_ip_broad_access(df)
    alerts += detect_privilege_escalation(df)
    return alerts
