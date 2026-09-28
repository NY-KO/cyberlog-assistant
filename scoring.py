RULE_WEIGHTS = {
    "brute_force": 30,
    "impossible_travel": 25,
    "unusual_hours": 10,
    "ip_broad_access": 20,
    "privilege_escalation": 30,
}

def score_alerts(alerts):
    per_user = {}
    for a in alerts:
        key = a["user"]
        per_user.setdefault(key, {"score": 0, "rules": []})
        per_user[key]["score"] += RULE_WEIGHTS.get(a["rule"], 10)
        per_user[key]["rules"].append(a)
    for v in per_user.values():
        v["score"] = min(v["score"], 100)
        v["level"] = (
            "Critical" if v["score"] >= 80 else
            "High" if v["score"] >= 60 else
            "Medium" if v["score"] >= 30 else "Low"
        )
    return per_user
