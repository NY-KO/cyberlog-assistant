import streamlit as st
import pandas as pd
from detection import run_all_detections
from scoring import score_alerts
from rule_explainer import generate_explanation

st.set_page_config(page_title="CyberLog Assistant", layout="wide")
st.title("🛡️ ルールベースのセキュリティログ分析アシスタント")
st.caption("学習・検証目的のプロトタイプです。検知・説明は全てルールベースで行われ、"
           "AIモデルは使用していません。実運用のSOC判断には使用しません。")

uploaded = st.file_uploader("セキュリティログ (CSV)", type="csv")
use_sample = st.checkbox("サンプルログを使う", value=True)

if uploaded or use_sample:
    df = pd.read_csv(uploaded) if uploaded else pd.read_csv("sample_logs.csv")
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    st.subheader("ログ概要")
    st.dataframe(df.head(20))

    with st.spinner("異常を検知中..."):
        alerts = run_all_detections(df)
        scored = score_alerts(alerts)

    st.subheader(f"検知結果：{len(scored)} 件の要確認ユーザー/IP")
    for user, info in sorted(scored.items(), key=lambda x: -x[1]["score"]):
        with st.expander(f"{user} — Risk {info['score']} ({info['level']})"):
            for r in info["rules"]:
                st.write(f"- **{r['rule']}**: {r['detail']}")
            if st.button(f"説明を表示: {user}", key=f"btn_{user}"):
                st.markdown(generate_explanation(user, info))
