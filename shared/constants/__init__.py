"""Shared constants for Threat Drill."""

# Gemini 3 Model Identifiers
GEMINI_3_FLASH = "gemini-3-flash"
GEMINI_3_PRO = "gemini-3-pro"
GEMINI_3_PRO_DEEP_THINK = "gemini-3-pro-deep-think"

# Context Window Sizes (tokens)
GEMINI_3_CONTEXT_WINDOW = 1_000_000  # 100万トークン
MAX_CONTEXT_FOR_ANALYSIS = 500_000

# Threat Detection Thresholds
THREAT_CONFIDENCE_THRESHOLD_HIGH = 0.9
THREAT_CONFIDENCE_THRESHOLD_MEDIUM = 0.7
THREAT_CONFIDENCE_THRESHOLD_LOW = 0.5

# Deep Think Activation Thresholds
DEEP_THINK_TRIGGER_CONFIDENCE = 0.75  # この値未満の場合Deep Thinkを起動
DEEP_THINK_TRIGGER_ANOMALY_SCORE = 0.8

# Response Time SLAs (milliseconds)
FLASH_RESPONSE_SLA = 100  # Flashは100ms以内
PRO_RESPONSE_SLA = 1000  # Proは1秒以内
DEEP_THINK_RESPONSE_SLA = 10000  # Deep Thinkは10秒以内

# Vector Search Settings
VECTOR_DIMENSION = 768  # Gemini embeddings dimension
SIMILARITY_THRESHOLD = 0.85
MAX_NEIGHBORS = 10

# Rate Limiting
MAX_REQUESTS_PER_MINUTE = 1000
MAX_REQUESTS_PER_HOUR = 50000

# Pub/Sub Topics
TOPIC_SECURITY_EVENTS = "threatdrill-security-events"
TOPIC_FEEDBACK_LOOP = "threatdrill-feedback-loop"
TOPIC_POLICY_UPDATES = "threatdrill-policy-updates"
TOPIC_RED_TEAM_FINDINGS = "threatdrill-red-team-findings"

# Firestore Collections
COLLECTION_POLICIES = "policies"
COLLECTION_SECURITY_EVENTS = "security_events"
COLLECTION_ATTACK_PATTERNS = "attack_patterns"
COLLECTION_SYSTEM_INSIGHTS = "system_insights"
COLLECTION_RBAC_RULES = "rbac_rules"

# Redis Cache Settings
CACHE_TTL_PATTERNS = 3600  # 1 hour
CACHE_TTL_POLICIES = 300  # 5 minutes
CACHE_TTL_EMBEDDINGS = 7200  # 2 hours

# Monitoring and Observability
PROMETHEUS_PORT = 9090
TRACE_SAMPLE_RATE = 0.1  # 10% sampling for production

# Red Teaming Configuration
RED_TEAM_FREQUENCY_HOURS = 24
RED_TEAM_MAX_CONCURRENT_ATTACKS = 5
RED_TEAM_TEST_ENVIRONMENTS = ["staging", "canary"]
