# CyberLog Assistant（ルールベース版）

## Problem
セキュリティログは量が多く、人手だけでは異常の見逃し・対応の遅れが起きやすい。

## Architecture
Logs → Pandas前処理 → ルールベース異常検知 → リスクスコアリング → ルールベース説明生成 → Streamlit UI

## Detection Logic
- Brute force / Impossible travel / Unusual hours / IP broad access / Privilege escalation
- 検知はすべてルールベース（可解釈性を優先）

## Risk Scoring
重みはプロトタイプ用の暫定値であり、実運用の基準ではない。

## Explanation Generation
本バージョンではAI/LLMは使用せず、検知ルールに対応した説明テンプレートから
文章を生成している。generate_explanation()のインターフェースは変えずに、
将来的にLLM API呼び出しへ差し替え可能な設計にしている。

## Limitations
- 学習・検証目的のプロトタイプであり、実運用のSOC自動遮断等には使用しない
- 誤検知・見逃しの可能性があり、最終判断は人間が行う設計
- サンプルデータはすべて架空のものであり、実データは一切含まない
- 現バージョンはAIモデルを使用しておらず、ルールベースの説明テンプレートのみで動作する

## Future Work
LLM APIとの連携による説明生成の高度化、MITRE ATT&CKマッピング、
教師あり異常検知モデルとの比較
