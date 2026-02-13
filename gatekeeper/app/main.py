"""Main FastAPI application for Gatekeeper."""

import asyncio
import os
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import make_asgi_app

from ..config import settings
from shared.utils import setup_logger, get_logger, MetricsCollector

# Windows: prefer subprocess-capable event loop (Playwright/MCP needs this).
# Some servers/libraries may pick Selector loop, which breaks asyncio subprocess APIs.
if os.name == "nt":
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    except Exception:
        pass

# ロガーとメトリクスの初期化
setup_logger(log_level=settings.log_level, json_logs=settings.json_logs)
logger = get_logger(__name__)
metrics = MetricsCollector()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """アプリケーションのライフサイクル管理."""
    logger.info("Starting Threat Drill Gatekeeper", version="1.0.0")

    # 起動時の初期化
    try:
        # Vertex AI クライアントの初期化などをここで実施
        logger.info("Initialization completed")
    except Exception as e:
        logger.error("Initialization failed", error=str(e))
        raise

    yield

    # シャットダウン時のクリーンアップ
    logger.info("Shutting down Threat Drill Gatekeeper")


# FastAPIアプリケーション
app = FastAPI(
    title="Threat Drill Security Platform",
    description="次世代AIエージェント専用の自己進化型セキュリティメッシュ",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS設定
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Prometheusメトリクスエンドポイント
if settings.enable_prometheus:
    metrics_app = make_asgi_app()
    app.mount("/metrics", metrics_app)


@app.middleware("http")
async def add_security_headers(request: Request, call_next: Any) -> Response:
    """セキュリティヘッダーの追加."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.middleware("http")
async def log_requests(request: Request, call_next: Any) -> Response:
    """リクエストのロギングと計測."""
    start_time = time.time()

    # リクエスト情報のログ
    logger.info(
        "Request received",
        method=request.method,
        path=request.url.path,
        client_ip=request.client.host if request.client else None,
    )

    try:
        response = await call_next(request)
        duration = time.time() - start_time

        # メトリクスの記録
        logger.info(
            "Request completed",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration=duration,
        )

        return response

    except Exception as e:
        duration = time.time() - start_time
        logger.error(
            "Request failed",
            method=request.method,
            path=request.url.path,
            error=str(e),
            duration=duration,
        )
        raise


@app.get("/health")
async def health_check() -> dict[str, str]:
    """ヘルスチェックエンドポイント."""
    return {"status": "healthy", "service": "threatdrill-gatekeeper"}


@app.get("/ready")
async def readiness_check() -> dict[str, str]:
    """レディネスチェックエンドポイント."""
    # TODO: Vertex AI, Firestoreへの接続確認
    return {"status": "ready", "service": "threatdrill-gatekeeper"}


from .routers import security, analysis, static_analysis, dynamic_proxy, red_team, blue_team, purple_team  # noqa: E402

# ルーターの登録
app.include_router(security.router, prefix="/api/v1/security", tags=["security"])
app.include_router(analysis.router, prefix="/api/v1/analysis", tags=["analysis"])
app.include_router(
    static_analysis.router,
    prefix="/api/v1/static-analysis",
    tags=["static-analysis"],
)
app.include_router(
    dynamic_proxy.router,
    prefix="/api/v1/dynamic-proxy",
    tags=["dynamic-proxy"],
)
app.include_router(
    red_team.router,
    prefix="/api/v1/red-team",
    tags=["red-team"],
)
app.include_router(
    blue_team.router,
    prefix="/api/v1/blue-team",
    tags=["blue-team"],
)
app.include_router(
    purple_team.router,
    prefix="/api/v1/purple-team",
    tags=["purple-team"],
)

# 静的ファイルとダッシュボード
STATIC_DIR = Path(__file__).parent / "static"


@app.get("/", include_in_schema=False)
async def root() -> FileResponse:
    """ダッシュボードページを返す."""
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
