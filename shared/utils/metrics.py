"""Metrics collection for monitoring and observability."""

from typing import Any, Dict

from prometheus_client import Counter, Histogram, Gauge


class MetricsCollector:
    """Prometheusメトリクス収集クラス."""

    def __init__(self) -> None:
        """メトリクスの初期化."""
        # リクエスト関連
        self.request_total = Counter(
            "aegisflow_requests_total",
            "Total number of security analysis requests",
            ["endpoint", "threat_level"],
        )

        self.request_duration = Histogram(
            "aegisflow_request_duration_seconds",
            "Request duration in seconds",
            ["endpoint", "model"],
        )

        # 脅威検知
        self.threats_detected = Counter(
            "aegisflow_threats_detected_total",
            "Total number of threats detected",
            ["threat_level", "pattern_type"],
        )

        self.threats_blocked = Counter(
            "aegisflow_threats_blocked_total",
            "Total number of threats blocked",
            ["threat_level"],
        )

        # Gemini モデル使用
        self.model_invocations = Counter(
            "aegisflow_model_invocations_total",
            "Total Gemini model invocations",
            ["model", "analysis_type"],
        )

        self.model_latency = Histogram(
            "aegisflow_model_latency_seconds",
            "Model inference latency",
            ["model"],
            buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0],
        )

        self.model_tokens_used = Counter(
            "aegisflow_model_tokens_total",
            "Total tokens consumed",
            ["model"],
        )

        # Deep Think使用
        self.deep_think_activations = Counter(
            "aegisflow_deep_think_activations_total",
            "Number of Deep Think mode activations",
            ["reason"],
        )

        # ポリシー更新
        self.policy_updates = Counter(
            "aegisflow_policy_updates_total",
            "Total policy updates",
            ["update_type", "auto_generated"],
        )

        # キャッシュヒット率
        self.cache_hits = Counter(
            "aegisflow_cache_hits_total",
            "Cache hits",
            ["cache_type"],
        )

        self.cache_misses = Counter(
            "aegisflow_cache_misses_total",
            "Cache misses",
            ["cache_type"],
        )

        # システム健全性
        self.system_health = Gauge(
            "aegisflow_system_health",
            "System health score (0-1)",
            ["component"],
        )

        # False positives/negatives
        self.false_positives = Counter(
            "aegisflow_false_positives_total",
            "False positive detections",
            ["pattern_type"],
        )

        self.false_negatives = Counter(
            "aegisflow_false_negatives_total",
            "False negative (missed threats)",
            ["attack_type"],
        )

    def record_request(
        self,
        endpoint: str,
        threat_level: str,
        duration: float,
        model: str,
    ) -> None:
        """リクエストメトリクスの記録."""
        self.request_total.labels(endpoint=endpoint, threat_level=threat_level).inc()
        self.request_duration.labels(endpoint=endpoint, model=model).observe(duration)

    def record_threat(self, threat_level: str, pattern_type: str, blocked: bool) -> None:
        """脅威検知メトリクスの記録."""
        self.threats_detected.labels(
            threat_level=threat_level, pattern_type=pattern_type
        ).inc()
        if blocked:
            self.threats_blocked.labels(threat_level=threat_level).inc()

    def record_model_usage(
        self,
        model: str,
        analysis_type: str,
        latency: float,
        tokens: int,
    ) -> None:
        """モデル使用メトリクスの記録."""
        self.model_invocations.labels(model=model, analysis_type=analysis_type).inc()
        self.model_latency.labels(model=model).observe(latency)
        self.model_tokens_used.labels(model=model).inc(tokens)

    def record_deep_think(self, reason: str) -> None:
        """Deep Think起動メトリクスの記録."""
        self.deep_think_activations.labels(reason=reason).inc()

    def get_metrics_summary(self) -> Dict[str, Any]:
        """メトリクスサマリーの取得."""
        return {
            "requests": self.request_total._value.get(),
            "threats_detected": self.threats_detected._value.get(),
            "threats_blocked": self.threats_blocked._value.get(),
        }
