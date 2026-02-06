"""GitHub Repository Analyzer for AI Application Security.

ファイル名ではなく、ファイルの内容をGemini 3で分析して判定します。
"""

import os
import re
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

import git
from github import Github, Repository

from shared.utils import get_logger

logger = get_logger(__name__)


@dataclass
class RepositoryFile:
    """リポジトリ内のファイル情報."""

    path: str
    content: str
    file_type: str
    size: int


@dataclass
class AIAppConfiguration:
    """AIアプリケーションの設定情報."""

    system_prompts: List[RepositoryFile]
    tool_definitions: List[RepositoryFile]
    config_files: List[RepositoryFile]
    code_files: List[RepositoryFile]
    rag_configs: List[RepositoryFile]
    api_keys_files: List[RepositoryFile]
    all_files: List[RepositoryFile]  # 全ファイル（未分類含む）


class GitHubRepositoryAnalyzer:
    """GitHubリポジトリを解析してAI関連ファイルを抽出."""

    CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb", ".txt", ".md", ".json", ".yaml", ".yml", ".toml"}

    # スキップするディレクトリ
    SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "dist", "build", "__pycache__"}

    def __init__(self, github_token: Optional[str] = None, gemini_client=None):
        """
        GitHubアナライザーの初期化.

        Args:
            github_token: GitHub Personal Access Token
            gemini_client: Gemini クライアント（内容分析用）
        """
        self.github_token = github_token
        self.github_client = Github(github_token) if github_token else None
        self.gemini_client = gemini_client

    def clone_repository(self, repo_url: str, target_dir: Optional[str] = None) -> Path:
        """
        GitHubリポジトリをクローン.

        Args:
            repo_url: リポジトリURL
            target_dir: クローン先ディレクトリ（Noneの場合は一時ディレクトリ）

        Returns:
            クローンされたディレクトリのパス
        """
        try:
            if target_dir is None:
                target_dir = tempfile.mkdtemp(prefix="threatdrill_")

            logger.info(
                "Cloning repository",
                repo_url=repo_url,
                target_dir=target_dir,
            )

            # Gitクローン実行
            git.Repo.clone_from(repo_url, target_dir)

            logger.info("Repository cloned successfully", target_dir=target_dir)
            return Path(target_dir)

        except Exception as e:
            logger.error("Failed to clone repository", error=str(e), repo_url=repo_url)
            raise

    async def classify_file_content(self, file_content: str, file_path: str) -> Optional[str]:
        """
        Gemini 3を使用してファイルの内容から役割を判定.

        Args:
            file_content: ファイルの内容
            file_path: ファイルパス（参考情報）

        Returns:
            ファイルの分類 ("system_prompt", "tool_definition", "config", "rag_config", "api_keys", "code", None)
        """
        if not self.gemini_client:
            # Geminiクライアントがない場合はキーワードベースの簡易分類
            return self._classify_by_keywords(file_content, file_path)

        # ファイルが空または短すぎる場合はスキップ
        if len(file_content.strip()) < 10:
            return None

        try:
            # Gemini 3で分析
            classification_prompt = f"""
以下のファイルの内容を分析し、このファイルがAIアプリケーションにおいてどの役割を持っているか判定してください。

ファイルパス: {file_path}
ファイル内容（最初の2000文字）:
```
{file_content[:2000]}
```

以下のカテゴリから1つ選択してください：

1. **system_prompt**: AIのSystem Prompt（システムプロンプト、指示文）
   - 特徴: "You are...", "あなたは...", "Act as...", AIへの役割定義や振る舞いの指示

2. **tool_definition**: AIが使用するツール・関数の定義
   - 特徴: function定義、tool定義、API呼び出し関数、database操作関数

3. **config**: アプリケーション設定ファイル
   - 特徴: model名、API endpoint、環境変数、一般的な設定項目

4. **rag_config**: RAG（Retrieval-Augmented Generation）関連の設定
   - 特徴: vector store設定、embedding設定、knowledge base設定

5. **api_keys**: APIキーや認証情報を含む可能性があるファイル
   - 特徴: API keys, tokens, passwords, credentials

6. **code**: AIロジックを含むコードファイル
   - 特徴: LLM呼び出し、agent実装、チャット機能のコード

7. **none**: 上記のいずれにも該当しない

JSON形式で以下のように回答してください：
{{
  "category": "system_prompt|tool_definition|config|rag_config|api_keys|code|none",
  "confidence": 0.0-1.0,
  "reasoning": "判定理由"
}}
"""

            # TODO: 実際のGemini API呼び出し
            # result = await self.gemini_client.analyze_with_flash(...)

            # モック: キーワードベース分類にフォールバック
            return self._classify_by_keywords(file_content, file_path)

        except Exception as e:
            logger.warning(
                "Failed to classify file with Gemini, using keyword-based classification",
                file_path=file_path,
                error=str(e),
            )
            return self._classify_by_keywords(file_content, file_path)

    def _classify_by_keywords(self, content: str, file_path: str) -> Optional[str]:
        """
        キーワードベースの簡易分類（Geminiが使えない場合のフォールバック）.

        Args:
            content: ファイル内容
            file_path: ファイルパス

        Returns:
            分類結果
        """
        content_lower = content.lower()

        # System Promptキーワード
        system_prompt_keywords = [
            "you are", "あなたは", "act as", "your role is",
            "system prompt", "system instruction", "assistant behavior",
            "instructions:", "role:", "behavior:",
        ]

        # Tool定義キーワード
        tool_keywords = [
            "def ", "function ", "async def", "tool_call", "function_call",
            "@tool", "tools.register", "function_calling",
            '"tools":', '"functions":', "tool_config",
        ]

        # RAG関連キーワード
        rag_keywords = [
            "vector", "embedding", "chroma", "pinecone", "weaviate",
            "faiss", "rag", "retrieval", "knowledge_base",
            "document_store", "vectorstore",
        ]

        # APIキーパターン
        api_key_patterns = [
            r"api[_-]?key",
            r"sk-[a-zA-Z0-9]{20,}",  # OpenAI形式
            r"AIza[0-9A-Za-z-_]{35}",  # Google API
            r"bearer\s+[a-zA-Z0-9]+",
            r"token\s*=",
            r"password\s*=",
            r"secret",
        ]

        # Config関連キーワード
        config_keywords = [
            "model:", "api_endpoint", "base_url", "temperature",
            "max_tokens", "settings", "configuration",
        ]

        # System Prompt判定
        if any(kw in content_lower for kw in system_prompt_keywords):
            # さらに確認：実際にプロンプトっぽい構造があるか
            if len(content) > 50 and ("you" in content_lower or "あなた" in content):
                return "system_prompt"

        # Tool定義判定
        if any(kw in content_lower for kw in tool_keywords):
            return "tool_definition"

        # RAG設定判定
        if any(kw in content_lower for kw in rag_keywords):
            return "rag_config"

        # APIキー判定
        for pattern in api_key_patterns:
            if re.search(pattern, content_lower):
                return "api_keys"

        # Config判定
        if any(kw in content_lower for kw in config_keywords):
            return "config"

        # AIコード判定
        ai_code_keywords = ["openai", "anthropic", "langchain", "llm", "chatgpt", "gpt-", "claude"]
        if any(kw in content_lower for kw in ai_code_keywords):
            return "code"

        return None

    async def scan_directory(self, directory: Path) -> AIAppConfiguration:
        """
        ディレクトリをスキャンしてAI関連ファイルを抽出.
        ファイル名ではなく内容から判定します。

        Args:
            directory: スキャン対象ディレクトリ

        Returns:
            AIアプリケーション設定情報
        """
        logger.info("Scanning directory for AI files (content-based)", directory=str(directory))

        system_prompts: List[RepositoryFile] = []
        tool_definitions: List[RepositoryFile] = []
        config_files: List[RepositoryFile] = []
        code_files: List[RepositoryFile] = []
        rag_configs: List[RepositoryFile] = []
        api_keys_files: List[RepositoryFile] = []
        all_files: List[RepositoryFile] = []

        # ディレクトリを再帰的にスキャン
        for file_path in directory.rglob("*"):
            if not file_path.is_file():
                continue

            # スキップディレクトリのチェック
            if any(skip_dir in file_path.parts for skip_dir in self.SKIP_DIRS):
                continue

            relative_path = file_path.relative_to(directory)
            path_str = str(relative_path)

            # コード系ファイルのみ処理
            if file_path.suffix not in self.CODE_EXTENSIONS:
                continue

            # ファイルサイズチェック（10MB以上はスキップ）
            if file_path.stat().st_size > 10 * 1024 * 1024:
                continue

            try:
                # テキストファイルを読み込み
                content = file_path.read_text(encoding="utf-8", errors="ignore")

                file_info = RepositoryFile(
                    path=path_str,
                    content=content,
                    file_type=file_path.suffix,
                    size=len(content),
                )

                all_files.append(file_info)

                # 内容から分類
                category = await self.classify_file_content(content, path_str)

                if category == "system_prompt":
                    system_prompts.append(file_info)
                    logger.info("Classified as system prompt (by content)", path=path_str)

                elif category == "tool_definition":
                    tool_definitions.append(file_info)
                    logger.info("Classified as tool definition (by content)", path=path_str)

                elif category == "config":
                    config_files.append(file_info)
                    logger.info("Classified as config (by content)", path=path_str)

                elif category == "rag_config":
                    rag_configs.append(file_info)
                    logger.info("Classified as RAG config (by content)", path=path_str)

                elif category == "api_keys":
                    api_keys_files.append(file_info)
                    logger.info("Classified as API keys file (by content)", path=path_str)

                elif category == "code":
                    code_files.append(file_info)
                    logger.debug("Classified as AI code (by content)", path=path_str)

            except Exception as e:
                logger.warning("Failed to read/classify file", path=path_str, error=str(e))
                continue

        config = AIAppConfiguration(
            system_prompts=system_prompts,
            tool_definitions=tool_definitions,
            config_files=config_files,
            code_files=code_files,
            rag_configs=rag_configs,
            api_keys_files=api_keys_files,
            all_files=all_files,
        )

        logger.info(
            "Directory scan completed (content-based classification)",
            system_prompts_count=len(system_prompts),
            tool_definitions_count=len(tool_definitions),
            config_files_count=len(config_files),
            code_files_count=len(code_files),
            rag_configs_count=len(rag_configs),
            api_keys_count=len(api_keys_files),
            total_files=len(all_files),
        )

        return config

    async def analyze_repository(self, repo_url: str) -> AIAppConfiguration:
        """
        GitHubリポジトリを解析（内容ベース）.

        Args:
            repo_url: GitHubリポジトリURL

        Returns:
            AIアプリケーション設定情報
        """
        logger.info("Starting content-based repository analysis", repo_url=repo_url)

        # クローン
        repo_dir = self.clone_repository(repo_url)

        try:
            # スキャン（内容ベース）
            config = await self.scan_directory(repo_dir)
            return config

        finally:
            # クリーンアップ
            try:
                shutil.rmtree(repo_dir)
                logger.info("Cleaned up temporary directory", directory=str(repo_dir))
            except Exception as e:
                logger.warning("Failed to cleanup directory", error=str(e))

    def create_pull_request(
        self,
        repo_url: str,
        branch_name: str,
        title: str,
        body: str,
        files_to_update: Dict[str, str],
    ) -> str:
        """
        セキュリティ修正PRを作成.

        Args:
            repo_url: リポジトリURL
            branch_name: ブランチ名
            title: PRタイトル
            body: PR本文
            files_to_update: {ファイルパス: 新しい内容}

        Returns:
            PR URL
        """
        if not self.github_client:
            raise ValueError("GitHub token is required to create pull requests")

        try:
            # リポジトリ名の抽出
            repo_name = repo_url.rstrip("/").split("/")[-2:]
            repo_full_name = "/".join(repo_name).replace(".git", "")

            repo = self.github_client.get_repo(repo_full_name)

            # デフォルトブランチを取得
            default_branch = repo.default_branch
            base_sha = repo.get_branch(default_branch).commit.sha

            # 新しいブランチを作成
            ref = f"refs/heads/{branch_name}"
            repo.create_git_ref(ref=ref, sha=base_sha)

            # ファイルを更新
            for file_path, new_content in files_to_update.items():
                try:
                    # 既存ファイルを取得
                    contents = repo.get_contents(file_path, ref=branch_name)
                    repo.update_file(
                        path=file_path,
                        message=f"[Threat Drill] Security fix for {file_path}",
                        content=new_content,
                        sha=contents.sha,
                        branch=branch_name,
                    )
                except Exception:
                    # ファイルが存在しない場合は新規作成
                    repo.create_file(
                        path=file_path,
                        message=f"[Threat Drill] Add security guardrails to {file_path}",
                        content=new_content,
                        branch=branch_name,
                    )

            # Pull Requestを作成
            pr = repo.create_pull(
                title=title,
                body=body,
                head=branch_name,
                base=default_branch,
            )

            logger.info(
                "Pull request created",
                pr_url=pr.html_url,
                pr_number=pr.number,
            )

            return pr.html_url

        except Exception as e:
            logger.error("Failed to create pull request", error=str(e))
            raise
