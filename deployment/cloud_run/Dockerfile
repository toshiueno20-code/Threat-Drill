# Threat Drill Gatekeeper - Cloud Run Dockerfile

FROM python:3.11-slim

# 作業ディレクトリの設定
WORKDIR /app

# システムパッケージのインストール
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Poetry のインストール
RUN pip install poetry==1.7.1

# 依存関係ファイルのコピー
COPY pyproject.toml poetry.lock* ./

# 依存関係のインストール（仮想環境を作成しない）
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-root --only main

# アプリケーションコードのコピー
COPY . .

# ポートの公開
EXPOSE 8080

# 非rootユーザーの作成と切り替え
RUN useradd -m -u 1000 threatdrill && chown -R threatdrill:threatdrill /app
USER threatdrill

# ヘルスチェック
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8080/health')"

# アプリケーションの起動
CMD ["uvicorn", "gatekeeper.app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "4"]
