"""Static Analysis endpoints for GitHub repository scanning."""

import tempfile
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, HttpUrl

from static_analyzer.github_integration.repo_analyzer import GitHubRepositoryAnalyzer
from static_analyzer.vulnerability_scanner.ai_app_scanner import AIAppSecurityScanner
from static_analyzer.report_generator.audit_report import SecurityAuditReportGenerator
from intelligence_center.models import GeminiClient
from gatekeeper.config import settings
from shared.utils import get_logger

logger = get_logger(__name__)
router = APIRouter()


class RepositoryScanRequest(BaseModel):
    """リポジトリスキャンリクエスト."""

    repository_url: HttpUrl
    github_token: Optional[str] = None
    create_pr: bool = False
    pr_branch_name: str = "threatdrill/security-fixes"


class RepositoryScanResponse(BaseModel):
    """リポジトリスキャンレスポンス."""

    scan_id: str
    status: str
    repository_url: str
    overall_score: Optional[float] = None
    vulnerabilities_count: Optional[int] = None
    report_json_url: Optional[str] = None
    report_pdf_url: Optional[str] = None
    pr_url: Optional[str] = None


@router.post("/scan", response_model=RepositoryScanResponse)
async def scan_repository(
    request: RepositoryScanRequest,
    background_tasks: BackgroundTasks,
) -> RepositoryScanResponse:
    """
    GitHubリポジトリをスキャンしてセキュリティ監査を実施.

    このエンドポイントは以下を実行します:
    1. リポジトリをクローン
    2. AI関連ファイル（System Prompt, Tool定義など）を抽出
    3. Gemini 3で脆弱性をスキャン
    4. セキュリティレポート（PDF/JSON）を生成
    5. （オプション）自動修正PRを作成
    """
    import uuid

    scan_id = str(uuid.uuid4())

    logger.info(
        "Repository scan requested",
        scan_id=scan_id,
        repository_url=str(request.repository_url),
    )

    try:
        # Geminiクライアントの初期化
        gemini_client = GeminiClient(
            api_key=settings.api_key,
            base_url=settings.gemini_api_base_url,
            flash_model=settings.gemini_flash_model,
            deep_model=settings.gemini_deep_model,
            embedding_model=settings.gemini_embed_model,
            project_id=settings.gcp_project_id,
            location=settings.gcp_location,
        )

        # GitHubアナライザーの初期化（Geminiクライアントを渡す）
        repo_analyzer = GitHubRepositoryAnalyzer(
            github_token=request.github_token,
            gemini_client=gemini_client,
        )

        # リポジトリ解析（内容ベース）
        logger.info("Analyzing repository (content-based)", scan_id=scan_id)
        config = await repo_analyzer.analyze_repository(str(request.repository_url))

        # 脆弱性スキャン
        scanner = AIAppSecurityScanner(gemini_client)
        audit_result = await scanner.scan_repository(
            repo_url=str(request.repository_url),
            config=config,
        )

        # レポート生成
        report_gen = SecurityAuditReportGenerator()

        # JSONレポート
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as json_file:
            json_path = Path(json_file.name)
            report_gen.generate_json_report(audit_result, json_path)
            # TODO: Cloud Storageにアップロード
            json_url = f"/reports/{scan_id}.json"

        # PDFレポート
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".pdf", delete=False
        ) as pdf_file:
            pdf_path = Path(pdf_file.name)
            report_gen.generate_pdf_report(audit_result, pdf_path)
            # TODO: Cloud Storageにアップロード
            pdf_url = f"/reports/{scan_id}.pdf"

        pr_url = None

        # 自動修正PRの作成（オプション）
        if request.create_pr and audit_result.auto_fix_available:
            logger.info("Creating auto-fix PR", scan_id=scan_id)

            # HTMLサマリーを生成
            html_summary = report_gen.generate_html_summary(audit_result)

            # 修正コードを生成
            files_to_update = {}
            for vuln in audit_result.vulnerabilities[:5]:  # 最初の5件のみ
                auto_fix = scanner.generate_auto_fix(vuln)
                if auto_fix and vuln.affected_files:
                    # 最初のファイルのみ修正
                    file_path = vuln.affected_files[0]
                    files_to_update[file_path] = auto_fix

            if files_to_update:
                try:
                    pr_url = repo_analyzer.create_pull_request(
                        repo_url=str(request.repository_url),
                        branch_name=request.pr_branch_name,
                        title="[Threat Drill] Security fixes for AI application",
                        body=html_summary,
                        files_to_update=files_to_update,
                    )
                    logger.info("Pull request created", pr_url=pr_url, scan_id=scan_id)
                except Exception as e:
                    logger.error("Failed to create PR", error=str(e), scan_id=scan_id)

        response = RepositoryScanResponse(
            scan_id=scan_id,
            status="completed",
            repository_url=str(request.repository_url),
            overall_score=audit_result.overall_score,
            vulnerabilities_count=len(audit_result.vulnerabilities),
            report_json_url=json_url,
            report_pdf_url=pdf_url,
            pr_url=pr_url,
        )

        logger.info(
            "Repository scan completed",
            scan_id=scan_id,
            overall_score=audit_result.overall_score,
            vulnerabilities_count=len(audit_result.vulnerabilities),
        )

        return response

    except Exception as e:
        logger.error(
            "Repository scan failed",
            scan_id=scan_id,
            error=str(e),
        )
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.get("/scan/{scan_id}", response_model=RepositoryScanResponse)
async def get_scan_status(scan_id: str) -> RepositoryScanResponse:
    """スキャン状態の取得."""
    # TODO: Firestoreから取得
    raise HTTPException(status_code=404, detail="Scan not found")


@router.get("/health")
async def static_analysis_health() -> dict:
    """Static Analysisモジュールのヘルスチェック."""
    return {"status": "healthy", "module": "static_analysis"}
