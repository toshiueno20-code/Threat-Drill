# AegisFlow AI

**～Gemini 3の深層思考を用いた、次世代AIエージェント専用の自己進化型セキュリティメッシュ～**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Google Cloud](https://img.shields.io/badge/Google%20Cloud-Vertex%20AI-4285F4)](https://cloud.google.com/vertex-ai)

## 概要

AegisFlow AIは、Gemini 3の高度な推論能力を活用した、次世代AIエージェント専用のセキュリティプラットフォームです。従来のセキュリティツールが単発のリクエストを監視するのに対し、AegisFlow AIは**100万トークン超のコンテキスト窓**をフル活用し、マルチステップ攻撃や画像・音声に埋め込まれた悪意のあるコマンドを検出します。

### 主要機能

1. **Real-time Multimodal Interceptor**
   Gemini 3 Flashによる超低遅延（<100ms）でテキスト、画像、音声、コード実行を同時に解析

2. **Deep Think Analyzer**
   疑わしい行動を検知した際、Gemini 3 Pro Deep Thinkモードが起動し、攻撃者の真の意図を深層推論。思考プロセスを可視化し、偽陽性（誤検知）を排除

3. **Self-Correction Policy Loop**
   攻撃を阻止した後、Gemini 3が「なぜこの攻撃が可能だったか」を分析し、防御プロンプトやRBACを自動で修正・再デプロイ

4. **Autonomous Red Teaming**
   内部の攻撃用エージェントが、常に最新の脆弱性データベースを元に自社システムを攻撃し続け、防御力を自己強化

## アーキテクチャ

```
┌─────────────────────────────────────────────────────────────┐
│                        User Request                         │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                  Gatekeeper (Cloud Run)                     │
│         FastAPI Proxy + Rate Limiting + RBAC                │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              Intelligence Center (Vertex AI)                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Primary Filter (Gemini 3 Flash)                    │   │
│  │  - <100ms response time                             │   │
│  │  - Multi-modal analysis (text/image/audio/code)     │   │
│  └──────────────────┬──────────────────────────────────┘   │
│                     │ confidence < 0.75?                   │
│                     ▼                                        │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Deep Think Analyzer (Gemini 3 Pro)                 │   │
│  │  - Complex threat reasoning                         │   │
│  │  - False positive elimination                       │   │
│  │  - Thought process visualization                    │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│          Policy Storage (Firestore + Vector Search)         │
│  - Attack pattern database                                  │
│  - Policy rules with vector embeddings                      │
│  - Security event history                                   │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│     Security Feedback Loop (Pub/Sub + Cloud Functions)      │
│  - Incident analysis                                        │
│  - Policy auto-correction                                   │
│  - System instruction updates                               │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              Autonomous Red Teaming (24/7)                  │
│  - Continuous attack simulation                             │
│  - Vulnerability discovery                                  │
│  - Defense strength validation                              │
└─────────────────────────────────────────────────────────────┘
```

## 技術スタック

| コンポーネント | 技術 | 説明 |
|:---|:---|:---|
| **高速検知エンジン** | Gemini 3 Flash | ミリ秒単位の推論、マルチモーダル理解 |
| **深層分析エンジン** | Gemini 3 Pro Deep Think | 思考プロセス可視化、高精度脅威判定 |
| **実行基盤** | Cloud Run | サーバーレス、自動スケーリング |
| **API Framework** | FastAPI | 高速、型安全、非同期処理 |
| **データベース** | Firestore | NoSQL、リアルタイム同期 |
| **ベクトルDB** | Vertex AI Vector Search | 大規模ベクトル検索 |
| **メッセージング** | Pub/Sub | イベント駆動アーキテクチャ |
| **モニタリング** | Prometheus + Looker | メトリクス収集と可視化 |

## セットアップ

### 前提条件

- Python 3.11+
- Docker
- Google Cloud SDK (`gcloud`)
- Poetry (Python dependency management)
- Google Cloud プロジェクト（Vertex AI有効化済み）

### インストール

1. **リポジトリのクローン**

```bash
git clone https://github.com/your-org/AegisFlow-AI.git
cd AegisFlow-AI
```

2. **依存関係のインストール**

```bash
poetry install
```

3. **環境変数の設定**

```bash
cp .env.example .env
# .env ファイルを編集してGoogle Cloud設定を記入
```

4. **ローカル開発サーバーの起動**

```bash
poetry run uvicorn gatekeeper.app.main:app --reload --port 8080
```

### Google Cloudへのデプロイ

1. **環境変数の設定**

```bash
export GCP_PROJECT_ID="your-project-id"
export GCP_REGION="us-central1"
```

2. **デプロイスクリプトの実行**

```bash
chmod +x scripts/deploy.sh
./scripts/deploy.sh
```

スクリプトは以下を自動的に実行します：
- 必要なGoogle Cloud APIの有効化
- Artifact Registryリポジトリの作成
- Firestoreデータベースの初期化
- Pub/Subトピックの作成
- サービスアカウントの作成とIAM権限付与
- Dockerイメージのビルドとプッシュ
- Cloud Runへのデプロイ

## 使い方

### セキュリティ分析APIの呼び出し

```bash
curl -X POST https://YOUR-SERVICE-URL/api/v1/security/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "inputs": [
      {
        "modality": "text",
        "content": "User input to analyze",
        "metadata": {},
        "timestamp": "2024-01-22T00:00:00Z"
      }
    ],
    "user_id": "user123",
    "session_id": "session456"
  }'
```

### レスポンス例

```json
{
  "event_id": "evt_abc123",
  "threat_analysis": {
    "threat_level": "safe",
    "confidence": 0.95,
    "reasoning": "No suspicious patterns detected",
    "detected_patterns": [],
    "recommended_actions": [],
    "deep_think_used": false,
    "analysis_duration_ms": 45.2,
    "model_version": "gemini-3-flash",
    "context_window_tokens": 1200
  },
  "blocked": false,
  "timestamp": "2024-01-22T00:00:05Z",
  "message": "Analysis completed successfully"
}
```

## プロジェクト構造

```
AegisFlow-AI/
├── gatekeeper/              # FastAPI Gatekeeperサービス
│   ├── app/                # アプリケーションコード
│   │   ├── main.py        # FastAPIエントリーポイント
│   │   └── routers/       # APIエンドポイント
│   └── config/            # 設定管理
├── intelligence_center/     # Gemini 3統合
│   ├── analyzers/         # 脅威分析エンジン
│   │   ├── primary_filter.py    # Gemini Flash高速フィルター
│   │   └── deep_think.py        # Gemini Pro Deep Think
│   └── models/            # Geminiクライアント
├── policy_storage/          # ポリシー管理
│   ├── firestore/         # Firestore統合
│   └── vector_search/     # ベクトル検索エンジン
├── feedback_loop/           # フィードバックループ
│   ├── cloud_functions/   # Cloud Functions
│   ├── pubsub/            # Pub/Sub統合
│   └── policy_engine/     # 自己修正エンジン
├── red_teaming/             # Red Teamingエージェント
│   ├── agents/            # 攻撃シミュレーションエージェント
│   └── scenarios/         # 攻撃シナリオ
├── shared/                  # 共有ユーティリティ
│   ├── schemas/           # Pydanticスキーマ
│   ├── constants/         # 定数定義
│   └── utils/             # ユーティリティ関数
├── deployment/              # デプロイメント設定
│   ├── cloud_run/         # Cloud Run設定
│   └── terraform/         # Terraform（将来実装）
├── scripts/                 # デプロイメントスクリプト
└── tests/                   # テストコード
```

## 主要コンポーネント

### 1. Gatekeeper (gatekeeper/)

FastAPIベースのプロキシサーバー。全てのリクエストをインターセプトし、セキュリティ分析を実施。

### 2. Intelligence Center (intelligence_center/)

Gemini 3を活用した脅威分析エンジン。
- **Primary Filter**: Gemini 3 Flashで高速スキャン
- **Deep Think Analyzer**: Gemini 3 Pro Deep Thinkで深層分析

### 3. Policy Storage (policy_storage/)

Firestoreとベクトル検索を使用したポリシー管理システム。

### 4. Feedback Loop (feedback_loop/)

Pub/SubとCloud Functionsを使用した自己修正システム。

### 5. Red Teaming (red_teaming/)

Gemini 3が生成した攻撃シナリオで継続的にシステムをテスト。

## モニタリングとメトリクス

### Prometheusメトリクス

```bash
# メトリクスエンドポイントにアクセス
curl https://YOUR-SERVICE-URL/metrics
```

主要メトリクス:
- `aegisflow_requests_total`: リクエスト総数
- `aegisflow_threats_detected_total`: 検知された脅威
- `aegisflow_threats_blocked_total`: ブロックされた脅威
- `aegisflow_model_invocations_total`: Gemini呼び出し回数
- `aegisflow_deep_think_activations_total`: Deep Think起動回数

### ログ

構造化ログ（JSON形式）がCloud Loggingに出力されます。

```bash
# Cloud Loggingでログを表示
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=aegisflow-gatekeeper" --limit 50
```

## セキュリティ

### Zero-Trust for AI

- 全てのAIエージェントのAPI呼び出しを動的検証
- ロールベースアクセス制御（RBAC）
- リクエストレート制限
- 入力サイズ制限

### データプライバシー

- センシティブデータは暗号化して保存
- PII（個人識別情報）の自動検出と保護
- GDPR/CCPA準拠

## ライセンス

MIT License - 詳細は [LICENSE](LICENSE) ファイルを参照してください。

## コントリビューション

コントリビューションを歓迎します！詳細は [CONTRIBUTING.md](CONTRIBUTING.md) を参照してください。

## サポート

- **Issue Tracker**: [GitHub Issues](https://github.com/your-org/AegisFlow-AI/issues)
- **Documentation**: [Wiki](https://github.com/your-org/AegisFlow-AI/wiki)

## ロードマップ

- [ ] Gemini 3 Live API統合
- [ ] Vertex AI Vector Searchフル統合
- [ ] Terraform IaCテンプレート
- [ ] Kubernetes/GKEデプロイメント対応
- [ ] マルチリージョン対応
- [ ] SOC 2 Type II準拠
- [ ] カスタムモデルファインチューニング

## 謝辞

このプロジェクトは、Google Cloud Vertex AI、Gemini 3、および最新のセキュリティ研究に基づいています。

---

**Built with ❤️ using Gemini 3**
