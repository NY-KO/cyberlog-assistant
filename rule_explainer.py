# ルールベースのテンプレートによる説明生成（外部API・AI連携なし）

RULE_INFO = {
    "brute_force": {
        "what": "短時間に大量のログイン失敗が発生し、その後成功ログインが確認されました。",
        "why": "同一アカウントへの反復的な認証試行はパスワード推測やクレデンシャルスタッフィングの典型的な兆候です。",
        "attack": "Brute Force / Credential Stuffing",
        "action": "該当アカウントの一時ロック、パスワードリセット、MFA有効化状況の確認を推奨します。",
    },
    "impossible_travel": {
        "what": "短時間のうちに異なる国からのログインが確認されました。",
        "why": "物理的に移動不可能な時間差での地理的変化は、アカウント乗っ取りの可能性を示唆します。",
        "attack": "Account Takeover",
        "action": "本人への確認、該当セッションの強制ログアウト、直近の操作履歴の確認を推奨します。",
    },
    "unusual_hours": {
        "what": "通常の業務時間外にアクティビティが検出されました。",
        "why": "深夜・早朝の操作は正規利用の場合もありますが、不正アクセスの可能性もあります。",
        "attack": "不明（要文脈確認）",
        "action": "業務上の正当な理由があるか本人・上長に確認することを推奨します。",
    },
    "ip_broad_access": {
        "what": "単一のIPアドレスから短時間に多数の異なるアカウントへのアクセスが試みられました。",
        "why": "1つの送信元から複数アカウントへの試行はスキャンや総当たり攻撃の可能性を示します。",
        "attack": "IP Scanning / Password Spraying",
        "action": "該当IPの一時遮断、関連するログの追加調査を推奨します。",
    },
    "privilege_escalation": {
        "what": "権限変更の直後にデータエクスポートが行われました。",
        "why": "権限昇格に続く即時のデータ持ち出しは、内部不正やアカウント侵害後の情報搾取に典型的なパターンです。",
        "attack": "Privilege Escalation / Data Exfiltration",
        "action": "エクスポートされたデータの範囲確認、権限変更の承認記録の確認を推奨します。",
    },
}

def generate_explanation(user, score_info):
    """ルールに対応するテンプレートから説明文を組み立てる（AI/外部API不使用）"""
    rules = score_info["rules"]
    triggered = sorted(set(r["rule"] for r in rules))

    what_list, why_list, attack_list, action_list = [], [], [], []
    for rule in triggered:
        info = RULE_INFO.get(rule)
        if not info:
            continue
        what_list.append(info["what"])
        why_list.append(info["why"])
        attack_list.append(info["attack"])
        action_list.append(info["action"])

    score = score_info["score"]
    confidence = "High" if score >= 80 else "Medium" if score >= 30 else "Low"

    return f"""**1. 何が起きたか**
{' '.join(what_list)}

**2. なぜ疑わしいか**
{' '.join(why_list)}

**3. 想定される攻撃種別**
{' / '.join(sorted(set(attack_list)))}

**4. 推奨対応**
{' '.join(action_list)}

**5. 信頼度**
{confidence}（リスクスコア {score} に基づく暫定判断）

**6. 限界・注意点**
本説明はルールベースのテンプレートから自動生成されたものであり、AIモデルによる
判断ではありません。誤検知の可能性があり、最終判断は必ず人が行ってください。
"""
