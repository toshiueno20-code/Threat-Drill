"""GitHub Repository Analyzer for AI Application Security."""

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


class GitHubRepositoryAnalyzer:
    """GitHubリポジトリを解析してAI関連ファイルを抽出."""

    # AI関連ファイルのパターン
    AI_PATTERNS = {
        "system_prompts": [
            r".*system[_-]?prompt.*\.(txt|md|json|yaml|yml)",
            r".*prompt.*template.*",
            r".*/prompts?/.*",
        ],
        "tool_definitions": [
            r".*tools?\.(py|js|ts|json)",
            r".*functions?\.(py|js|ts|json)",
            r".*function[_-]?calling.*",
            r".*tool[_-]?config.*",
        ],
        "config_files": [
            r".*app[_-]?config\.(yaml|yml|json|toml)",
            r".*\.?env.*",
            r".*config\.(yaml|yml|json|toml)",
            r".*settings\.(py|js|ts)",
        ],
        "rag_configs": [
            r".*rag.*config.*",
            r".*vector.*store.*",
            r".*embedding.*config.*",
            r".*knowledge.*base.*",
        ],
        "api_keys": [
            r".*\.env.*",
            r".*secrets?.*",
            r".*credentials?.*",
            r".*api[_-]?keys?.*",
        ],
    }

    CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb"}

    def __init__(self, github_token: Optional[str] = None):
        """
        GitHubアナライザーの初期化.

        Args:
            github_token: GitHub Personal Access Token
        """
        self.github_token = github_token
        self.github_client = Github(github_token) if github_token else None

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
                target_dir = tempfile.mkdtemp(prefix="aegisflow_")

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

    def scan_directory(self, directory: Path) -> AIAppConfiguration:
        """
        ディレクトリをスキャンしてAI関連ファイルを抽出.

        Args:
            directory: スキャン対象ディレクトリ

        Returns:
            AIアプリケーション設定情報
        """
        logger.info("Scanning directory for AI files", directory=str(directory))

        system_prompts: List[RepositoryFile] = []
        tool_definitions: List[RepositoryFile] = []
        config_files: List[RepositoryFile] = []
        code_files: List[RepositoryFile] = []
        rag_configs: List[RepositoryFile] = []
        api_keys_files: List[RepositoryFile] = []

        # ディレクトリを再帰的にスキャン
        for file_path in directory.rglob("*"):
            if not file_path.is_file():
                continue

            # .gitディレクトリやnode_modulesなどをスキップ
            if any(part.startswith(".") or part == "node_modules" for part in file_path.parts):
                continue

            relative_path = file_path.relative_to(directory)
            path_str = str(relative_path)

            # ファイルサイズチェック（10MB以上はスキップ）
            if file_path.stat().st_size > 10 * 1024 * 1024:
                continue

            try:
                # テキストファイルのみ読み込み
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                file_info = RepositoryFile(
                    path=path_str,
                    content=content,
                    file_type=file_path.suffix,
                    size=len(content),
                )

                # パターンマッチング
                if self._matches_patterns(path_str, self.AI_PATTERNS["system_prompts"]):
                    system_prompts.append(file_info)
                    logger.debug("Found system prompt file", path=path_str)

                elif self._matches_patterns(path_str, self.AI_PATTERNS["tool_definitions"]):
                    tool_definitions.append(file_info)
                    logger.debug("Found tool definition file", path=path_str)

                elif self._matches_patterns(path_str, self.AI_PATTERNS["config_files"]):
                    config_files.append(file_info)
                    logger.debug("Found config file", path=path_str)

                elif self._matches_patterns(path_str, self.AI_PATTERNS["rag_configs"]):
                    rag_configs.append(file_info)
                    logger.debug("Found RAG config file", path=path_str)

                elif self._matches_patterns(path_str, self.AI_PATTERNS["api_keys"]):
                    api_keys_files.append(file_info)
                    logger.debug("Found API keys file", path=path_str)

                # コードファイル
                elif file_path.suffix in self.CODE_EXTENSIONS:
                    # AI関連キーワードを含むコードファイルのみ
                    if self._contains_ai_keywords(content):
                        code_files.append(file_info)
                        logger.debug("Found AI-related code file", path=path_str)

            except Exception as e:
                logger.warning("Failed to read file", path=path_str, error=str(e))
                continue

        config = AIAppConfiguration(
            system_prompts=system_prompts,
            tool_definitions=tool_definitions,
            config_files=config_files,
            code_files=code_files,
            rag_configs=rag_configs,
            api_keys_files=api_keys_files,
        )

        logger.info(
            "Directory scan completed",
            system_prompts_count=len(system_prompts),
            tool_definitions_count=len(tool_definitions),
            config_files_count=len(config_files),
            code_files_count=len(code_files),
            rag_configs_count=len(rag_configs),
            api_keys_count=len(api_keys_files),
        )

        return config

    def _matches_patterns(self, path: str, patterns: List[str]) -> bool:
        """パスがパターンにマッチするかチェック."""
        path_lower = path.lower()
        return any(re.match(pattern, path_lower, re.IGNORECASE) for pattern in patterns)

    def _contains_ai_keywords(self, content: str) -> bool:
        """コンテンツにAI関連キーワードが含まれるかチェック."""
        ai_keywords = [
            "openai",
            "anthropic",
            "gemini",
            "langchain",
            "llama",
            "claude",
            "gpt",
            "chatgpt",
            "ai_model",
            "llm",
            "embedding",
            "vector_store",
            "rag",
            "agent",
            "tool_call",
            "function_call",
        ]

        content_lower = content.lower()
        return any(keyword in content_lower for keyword in ai_keywords)

    def analyze_repository(self, repo_url: str) -> AIAppConfiguration:
        """
        GitHubリポジトリを解析.

        Args:
            repo_url: GitHubリポジトリURL

        Returns:
            AIアプリケーション設定情報
        """
        logger.info("Starting repository analysis", repo_url=repo_url)

        # クローン
        repo_dir = self.clone_repository(repo_url)

        try:
            # スキャン
            config = self.scan_directory(repo_dir)
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
                        message=f"[AegisFlow] Security fix for {file_path}",
                        content=new_content,
                        sha=contents.sha,
                        branch=branch_name,
                    )
                except Exception:
                    # ファイルが存在しない場合は新規作成
                    repo.create_file(
                        path=file_path,
                        message=f"[AegisFlow] Add security guardrails to {file_path}",
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
