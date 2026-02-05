"""Vector search engine for pattern matching."""

import numpy as np
from typing import List, Tuple, Optional, Dict, Any

from shared.constants import (
    VECTOR_DIMENSION,
    SIMILARITY_THRESHOLD,
    MAX_NEIGHBORS,
)
from shared.schemas import AttackPattern
from shared.utils import get_logger

logger = get_logger(__name__)


class VectorSearchEngine:
    """ベクトル類似度検索エンジン."""

    def __init__(self):
        """VectorSearchEngineの初期化."""
        self.patterns: Dict[str, AttackPattern] = {}
        self.embeddings: Dict[str, np.ndarray] = {}

        logger.info("VectorSearchEngine initialized")

    def index_pattern(self, pattern: AttackPattern) -> None:
        """
        攻撃パターンをインデックスに追加.

        Args:
            pattern: 攻撃パターン
        """
        try:
            if not pattern.vector_embedding or len(pattern.vector_embedding) != VECTOR_DIMENSION:
                logger.warning(
                    "Invalid vector dimension for pattern",
                    pattern_id=pattern.pattern_id,
                    expected=VECTOR_DIMENSION,
                    actual=len(pattern.vector_embedding) if pattern.vector_embedding else 0,
                )
                return

            self.patterns[pattern.pattern_id] = pattern
            self.embeddings[pattern.pattern_id] = np.array(pattern.vector_embedding)

            logger.info(
                "Pattern indexed",
                pattern_id=pattern.pattern_id,
                total_patterns=len(self.patterns),
            )

        except Exception as e:
            logger.error(
                "Failed to index pattern",
                pattern_id=pattern.pattern_id,
                error=str(e),
            )
            raise

    def search_similar(
        self,
        query_embedding: List[float],
        k: int = MAX_NEIGHBORS,
        threshold: float = SIMILARITY_THRESHOLD,
    ) -> List[Tuple[AttackPattern, float]]:
        """
        類似パターンの検索.

        Args:
            query_embedding: クエリベクトル
            k: 取得する最大件数
            threshold: 類似度閾値

        Returns:
            (パターン, 類似度スコア) のリスト
        """
        try:
            if not self.embeddings:
                logger.warning("No patterns indexed yet")
                return []

            query_vec = np.array(query_embedding)
            if len(query_vec) != VECTOR_DIMENSION:
                raise ValueError(
                    f"Invalid query dimension: expected {VECTOR_DIMENSION}, got {len(query_vec)}"
                )

            # コサイン類似度の計算
            similarities: List[Tuple[str, float]] = []

            for pattern_id, pattern_vec in self.embeddings.items():
                similarity = self._cosine_similarity(query_vec, pattern_vec)
                if similarity >= threshold:
                    similarities.append((pattern_id, similarity))

            # 類似度でソート
            similarities.sort(key=lambda x: x[1], reverse=True)

            # 上位k件を取得
            results = [
                (self.patterns[pattern_id], score)
                for pattern_id, score in similarities[:k]
            ]

            logger.info(
                "Similar patterns found",
                query_matches=len(results),
                threshold=threshold,
            )

            return results

        except Exception as e:
            logger.error("Vector search failed", error=str(e))
            raise

    def _cosine_similarity(self, vec1: np.ndarray, vec2: np.ndarray) -> float:
        """
        コサイン類似度の計算.

        Args:
            vec1: ベクトル1
            vec2: ベクトル2

        Returns:
            コサイン類似度 (0.0 - 1.0)
        """
        dot_product = np.dot(vec1, vec2)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)

        if norm1 == 0 or norm2 == 0:
            return 0.0

        similarity = dot_product / (norm1 * norm2)
        # [-1, 1] を [0, 1] に正規化
        return float((similarity + 1) / 2)

    def remove_pattern(self, pattern_id: str) -> None:
        """
        パターンをインデックスから削除.

        Args:
            pattern_id: パターンID
        """
        try:
            if pattern_id in self.patterns:
                del self.patterns[pattern_id]
                del self.embeddings[pattern_id]

                logger.info(
                    "Pattern removed from index",
                    pattern_id=pattern_id,
                    remaining_patterns=len(self.patterns),
                )

        except Exception as e:
            logger.error(
                "Failed to remove pattern",
                pattern_id=pattern_id,
                error=str(e),
            )
            raise

    def clear(self) -> None:
        """インデックスをクリア."""
        self.patterns.clear()
        self.embeddings.clear()
        logger.info("Vector index cleared")

    def get_stats(self) -> Dict[str, Any]:
        """インデックスの統計情報を取得."""
        return {
            "total_patterns": len(self.patterns),
            "vector_dimension": VECTOR_DIMENSION,
            "similarity_threshold": SIMILARITY_THRESHOLD,
        }


class VertexAIVectorSearchEngine:
    """
    Vertex AI Vector Searchを使用した大規模ベクトル検索.

    注: 実際の実装にはVertex AI Vector Search APIの統合が必要
    """

    def __init__(
        self,
        project_id: str,
        location: str,
        index_endpoint: Optional[str] = None,
    ):
        """
        Vertex AI Vector Searchの初期化.

        Args:
            project_id: Google Cloud Project ID
            location: リージョン
            index_endpoint: Vector Searchインデックスエンドポイント
        """
        self.project_id = project_id
        self.location = location
        self.index_endpoint = index_endpoint

        logger.info(
            "VertexAIVectorSearchEngine initialized",
            project_id=project_id,
            location=location,
        )

    async def search(
        self,
        query_embedding: List[float],
        k: int = MAX_NEIGHBORS,
    ) -> List[Tuple[str, float]]:
        """
        Vertex AI Vector Searchで検索.

        Args:
            query_embedding: クエリベクトル
            k: 取得する最大件数

        Returns:
            (パターンID, 類似度スコア) のリスト
        """
        # TODO: Vertex AI Vector Search APIの統合
        logger.info("Vertex AI Vector Search query", k=k)
        return []

    async def upsert(
        self,
        pattern_id: str,
        embedding: List[float],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        ベクトルをインデックスに追加/更新.

        Args:
            pattern_id: パターンID
            embedding: ベクトル埋め込み
            metadata: メタデータ
        """
        # TODO: Vertex AI Vector Search APIの統合
        logger.info("Upserting to Vertex AI Vector Search", pattern_id=pattern_id)
