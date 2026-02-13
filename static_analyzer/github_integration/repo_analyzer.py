"""GitHub repository analyzer for AI application security scanning."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import unquote, urlparse

import git
from github import Github

from shared.utils import get_logger

logger = get_logger(__name__)


@dataclass
class RepositoryFile:
    """Repository file metadata used by the scanner."""

    path: str
    content: str
    file_type: str
    size: int


@dataclass
class AIAppConfiguration:
    """Classified repository files relevant to AI security scanning."""

    system_prompts: List[RepositoryFile]
    tool_definitions: List[RepositoryFile]
    config_files: List[RepositoryFile]
    code_files: List[RepositoryFile]
    rag_configs: List[RepositoryFile]
    api_keys_files: List[RepositoryFile]
    all_files: List[RepositoryFile]


@dataclass
class CloneContext:
    """Resolved clone and scan context derived from a repository URL."""

    repo_dir: Path
    scan_dir: Path
    normalized_repo_url: str
    selected_branch: Optional[str] = None
    selected_subpath: Optional[str] = None


class GitHubRepositoryAnalyzer:
    """Analyze repository contents and classify files for security scanning."""

    CODE_EXTENSIONS = {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".go",
        ".java",
        ".rb",
        ".txt",
        ".md",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
    }

    SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "dist", "build", "__pycache__"}

    def __init__(self, github_token: Optional[str] = None, gemini_client=None):
        self.github_token = github_token
        self.github_client = Github(github_token) if github_token else None
        self.gemini_client = gemini_client
        self._ai_classification_enabled = bool(gemini_client and getattr(gemini_client, "_api_enabled", False))
        self._ai_classification_budget = 12

    @staticmethod
    def _remove_readonly(func, path: str, _exc_info) -> None:
        """Retry path deletion after converting readonly files to writable."""
        try:
            os.chmod(path, stat.S_IWRITE)
            func(path)
        except Exception:
            pass

    @staticmethod
    def _safe_float(value: Any, default: float = 0.0) -> float:
        try:
            return float(value)
        except Exception:
            return default

    @staticmethod
    def _extract_json_payload(text: str) -> Dict[str, Any]:
        """Extract a JSON object from free-form model text."""
        if not text:
            return {}

        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass

        try:
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if match:
                parsed = json.loads(match.group())
                if isinstance(parsed, dict):
                    return parsed
        except Exception:
            pass

        return {}

    @staticmethod
    def _normalize_category(raw: Any) -> Optional[str]:
        """Normalize model category aliases to known category names."""
        allowed = {"system_prompt", "tool_definition", "config", "rag_config", "api_keys", "code", "none"}
        if raw is None:
            return None

        category = str(raw).strip().lower()
        aliases = {
            "system": "system_prompt",
            "systemprompt": "system_prompt",
            "tool": "tool_definition",
            "tools": "tool_definition",
            "tool_definitions": "tool_definition",
            "configuration": "config",
            "rag": "rag_config",
            "secret": "api_keys",
            "secrets": "api_keys",
            "api_key": "api_keys",
            "api": "api_keys",
            "source_code": "code",
        }
        category = aliases.get(category, category)
        if category in allowed:
            return None if category == "none" else category
        return None

    def _normalize_github_url(self, repo_url: str) -> tuple[str, list[str]]:
        """Normalize clone URL and return tree/blob tail tokens if present."""
        parsed = urlparse(repo_url)
        host = (parsed.netloc or "").lower()
        parts = [unquote(part) for part in parsed.path.strip("/").split("/") if part]

        if host not in {"github.com", "www.github.com"} or len(parts) < 2:
            return repo_url, []

        owner = parts[0]
        repo = parts[1].removesuffix(".git")
        normalized = f"https://github.com/{owner}/{repo}.git"

        if len(parts) >= 4 and parts[2] in {"tree", "blob"}:
            return normalized, parts[3:]

        return normalized, []

    @staticmethod
    def _resolve_branch_from_tokens(repo: git.Repo, tree_tokens: list[str]) -> tuple[Optional[str], Optional[str]]:
        """Resolve branch and optional subpath from tree URL tokens."""
        if not tree_tokens:
            return None, None

        remote_branches = {
            ref.remote_head
            for ref in repo.remotes.origin.refs
            if getattr(ref, "remote_head", "") and ref.remote_head != "HEAD"
        }

        for i in range(len(tree_tokens), 0, -1):
            branch = "/".join(tree_tokens[:i])
            if branch in remote_branches:
                subpath = "/".join(tree_tokens[i:]) or None
                return branch, subpath

        branch = tree_tokens[0]
        subpath = "/".join(tree_tokens[1:]) or None
        return branch, subpath

    def clone_repository(self, repo_url: str, target_dir: Optional[str] = None) -> CloneContext:
        """Clone repository and resolve branch/subpath when tree URL is provided."""
        repo: Optional[git.Repo] = None
        try:
            if target_dir is None:
                target_dir = tempfile.mkdtemp(prefix="threatdrill_")

            normalized_repo_url, tree_tokens = self._normalize_github_url(repo_url)
            logger.info(
                "Cloning repository",
                source_url=repo_url,
                normalized_repo_url=normalized_repo_url,
                target_dir=target_dir,
            )

            repo = git.Repo.clone_from(normalized_repo_url, target_dir)
            selected_branch = None
            selected_subpath = None

            if tree_tokens:
                branch_hint, subpath_hint = self._resolve_branch_from_tokens(repo, tree_tokens)
                if branch_hint:
                    try:
                        repo.git.checkout(branch_hint)
                        selected_branch = branch_hint
                        selected_subpath = subpath_hint
                    except Exception as checkout_error:
                        logger.warning(
                            "Branch checkout failed; using default branch",
                            branch=branch_hint,
                            error=str(checkout_error),
                        )

            repo_dir = Path(target_dir)
            scan_dir = repo_dir
            if selected_subpath:
                candidate_scan_dir = repo_dir / selected_subpath
                if candidate_scan_dir.exists() and candidate_scan_dir.is_dir():
                    scan_dir = candidate_scan_dir
                else:
                    logger.warning(
                        "Requested subpath not found; scanning repository root",
                        subpath=selected_subpath,
                    )
                    selected_subpath = None

            return CloneContext(
                repo_dir=repo_dir,
                scan_dir=scan_dir,
                normalized_repo_url=normalized_repo_url,
                selected_branch=selected_branch,
                selected_subpath=selected_subpath,
            )

        except Exception as exc:
            logger.error("Failed to clone repository", error=str(exc), repo_url=repo_url)
            raise
        finally:
            if repo is not None:
                try:
                    repo.close()
                except Exception:
                    pass

    async def classify_file_content(self, file_content: str, file_path: str) -> Optional[str]:
        """Classify a file using Gemini first, with keyword fallback."""
        if len(file_content.strip()) < 10:
            return None

        keyword_category = self._classify_by_keywords(file_content, file_path)
        if not self._ai_classification_enabled or self._ai_classification_budget <= 0:
            return keyword_category

        # Use AI only when keyword rules are inconclusive.
        if keyword_category is not None:
            return keyword_category

        if self.gemini_client:
            try:
                self._ai_classification_budget -= 1
                system_instruction = (
                    "You classify repository files for AI security analysis. "
                    "Return strict JSON only: "
                    '{"category":"system_prompt|tool_definition|config|rag_config|api_keys|code|none",'
                    '"confidence":0.0,"reasoning":"short reason"}. '
                    "Do not use markdown."
                )
                classification_prompt = (
                    f"File path: {file_path}\n\n"
                    "File content (first 2500 chars):\n"
                    f"{file_content[:2500]}"
                )

                analysis = await self.gemini_client.analyze_with_flash(
                    inputs=[{"type": "text", "text": classification_prompt}],
                    system_instruction=system_instruction,
                )
                if analysis.get("provider_fallback"):
                    self._ai_classification_enabled = False
                    return keyword_category

                category = self._normalize_category(analysis.get("category"))
                confidence = self._safe_float(analysis.get("confidence"), 0.0)

                if not category:
                    parsed = self._extract_json_payload(str(analysis.get("reasoning", "")))
                    category = self._normalize_category(parsed.get("category"))
                    if confidence <= 0:
                        confidence = self._safe_float(parsed.get("confidence"), 0.0)

                if category and confidence >= 0.55:
                    logger.info(
                        "Classified file with Gemini",
                        path=file_path,
                        category=category,
                        confidence=round(confidence, 3),
                    )
                    return category

                logger.debug(
                    "Gemini classification low-confidence; using keyword fallback",
                    path=file_path,
                    suggested_category=category,
                    confidence=round(confidence, 3),
                )
            except Exception as exc:
                logger.warning(
                    "Failed to classify file with Gemini; using keyword fallback",
                    file_path=file_path,
                    error=str(exc),
                )
                # Fail fast after provider-level errors to avoid repeated slow calls.
                self._ai_classification_enabled = False

        return keyword_category

    def _classify_by_keywords(self, content: str, file_path: str) -> Optional[str]:
        """Fallback keyword classification for offline mode or low-confidence AI output."""
        del file_path  # reserved for future path-based hints
        content_lower = content.lower()

        system_prompt_keywords = [
            "you are",
            "act as",
            "your role is",
            "system prompt",
            "system instruction",
            "assistant behavior",
            "instructions:",
            "role:",
            "behavior:",
        ]
        tool_keywords = [
            "def ",
            "function ",
            "async def",
            "tool_call",
            "function_call",
            "@tool",
            "tools.register",
            "function_calling",
            '"tools":',
            '"functions":',
            "tool_config",
        ]
        rag_keywords = [
            "vector",
            "embedding",
            "chroma",
            "pinecone",
            "weaviate",
            "faiss",
            "rag",
            "retrieval",
            "knowledge_base",
            "document_store",
            "vectorstore",
        ]
        api_key_patterns = [
            r"api[_-]?key",
            r"sk-[a-zA-Z0-9]{20,}",
            r"AIza[0-9A-Za-z-_]{35}",
            r"bearer\s+[a-zA-Z0-9]+",
            r"token\s*=",
            r"password\s*=",
            r"secret",
        ]
        config_keywords = [
            "model:",
            "api_endpoint",
            "base_url",
            "temperature",
            "max_tokens",
            "settings",
            "configuration",
        ]

        if any(keyword in content_lower for keyword in system_prompt_keywords):
            if len(content) > 50 and ("you" in content_lower or "assistant" in content_lower):
                return "system_prompt"

        if any(keyword in content_lower for keyword in tool_keywords):
            return "tool_definition"

        if any(keyword in content_lower for keyword in rag_keywords):
            return "rag_config"

        for pattern in api_key_patterns:
            if re.search(pattern, content_lower):
                return "api_keys"

        if any(keyword in content_lower for keyword in config_keywords):
            return "config"

        ai_code_keywords = ["openai", "anthropic", "langchain", "llm", "chatgpt", "gpt-", "claude", "gemini"]
        if any(keyword in content_lower for keyword in ai_code_keywords):
            return "code"

        return None

    async def scan_directory(self, directory: Path) -> AIAppConfiguration:
        """Scan repository directory and classify source files by content."""
        logger.info("Scanning directory for AI files (content-based)", directory=str(directory))

        system_prompts: List[RepositoryFile] = []
        tool_definitions: List[RepositoryFile] = []
        config_files: List[RepositoryFile] = []
        code_files: List[RepositoryFile] = []
        rag_configs: List[RepositoryFile] = []
        api_keys_files: List[RepositoryFile] = []
        all_files: List[RepositoryFile] = []

        for file_path in directory.rglob("*"):
            if not file_path.is_file():
                continue

            if any(skip_dir in file_path.parts for skip_dir in self.SKIP_DIRS):
                continue

            if file_path.suffix not in self.CODE_EXTENSIONS:
                continue

            if file_path.stat().st_size > 10 * 1024 * 1024:
                continue

            relative_path = file_path.relative_to(directory)
            path_str = str(relative_path)

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                file_info = RepositoryFile(
                    path=path_str,
                    content=content,
                    file_type=file_path.suffix,
                    size=len(content),
                )
                all_files.append(file_info)

                category = await self.classify_file_content(content, path_str)
                if category == "system_prompt":
                    system_prompts.append(file_info)
                    logger.info("Classified as system prompt", path=path_str)
                elif category == "tool_definition":
                    tool_definitions.append(file_info)
                    logger.info("Classified as tool definition", path=path_str)
                elif category == "config":
                    config_files.append(file_info)
                    logger.info("Classified as config", path=path_str)
                elif category == "rag_config":
                    rag_configs.append(file_info)
                    logger.info("Classified as RAG config", path=path_str)
                elif category == "api_keys":
                    api_keys_files.append(file_info)
                    logger.info("Classified as API key file", path=path_str)
                elif category == "code":
                    code_files.append(file_info)
                    logger.debug("Classified as AI code", path=path_str)

            except Exception as exc:
                logger.warning("Failed to read/classify file", path=path_str, error=str(exc))
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
            "Directory scan completed",
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
        """Clone a repository and return classified AI-relevant files."""
        logger.info("Starting content-based repository analysis", repo_url=repo_url)

        clone_ctx = self.clone_repository(repo_url)
        try:
            return await self.scan_directory(clone_ctx.scan_dir)
        finally:
            try:
                shutil.rmtree(clone_ctx.repo_dir, onerror=self._remove_readonly)
                logger.info("Cleaned up temporary directory", directory=str(clone_ctx.repo_dir))
            except Exception as exc:
                logger.warning("Failed to cleanup directory", error=str(exc))

    def create_pull_request(
        self,
        repo_url: str,
        branch_name: str,
        title: str,
        body: str,
        files_to_update: Dict[str, str],
    ) -> str:
        """Create a pull request with generated security fixes."""
        if not self.github_client:
            raise ValueError("GitHub token is required to create pull requests")

        try:
            normalized_repo_url, _ = self._normalize_github_url(repo_url)
            parsed = urlparse(normalized_repo_url)
            path_parts = [part for part in parsed.path.strip("/").split("/") if part]
            if len(path_parts) < 2:
                raise ValueError(f"Invalid GitHub repository URL: {repo_url}")

            repo_full_name = f"{path_parts[0]}/{path_parts[1].removesuffix('.git')}"
            repo = self.github_client.get_repo(repo_full_name)

            default_branch = repo.default_branch
            base_sha = repo.get_branch(default_branch).commit.sha

            repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=base_sha)

            for file_path, new_content in files_to_update.items():
                try:
                    current = repo.get_contents(file_path, ref=branch_name)
                    repo.update_file(
                        path=file_path,
                        message=f"[Threat Drill] Security fix for {file_path}",
                        content=new_content,
                        sha=current.sha,
                        branch=branch_name,
                    )
                except Exception:
                    repo.create_file(
                        path=file_path,
                        message=f"[Threat Drill] Add security guardrails to {file_path}",
                        content=new_content,
                        branch=branch_name,
                    )

            pull_request = repo.create_pull(
                title=title,
                body=body,
                head=branch_name,
                base=default_branch,
            )

            logger.info("Pull request created", pr_url=pull_request.html_url, pr_number=pull_request.number)
            return pull_request.html_url

        except Exception as exc:
            logger.error("Failed to create pull request", error=str(exc))
            raise
