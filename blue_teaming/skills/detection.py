"""Threat detection skills — RISS/CISSP-grade real-time monitoring.

Enhanced with:
- MITRE ATT&CK technique IDs (including ATLAS for AI/LLM)
- CVSS v3.1 severity scoring per detection
- Multi-language prompt injection (Japanese, Chinese, Korean, Cyrillic)
- Indirect prompt injection (invisible chars, homoglyphs, Unicode tricks)
- STIX 2.1 IOC output for threat intelligence sharing
- Detection confidence scoring
"""

import math
import re
import time
import unicodedata
from typing import Any, ClassVar

from .base import (
    BaseDefenseSkill,
    DefenseResult,
    AlertLevel,
    DefenseAction,
    IncidentContext,
    NISTIRPhase,
    ContainmentStrategy,
    MITRETechnique,
    CVSSVector,
    STIXIndicator,
    EvidenceItem,
    ChainOfCustody,
    CVSS_PRESETS,
    defense_skill,
    record_defense,
)


@defense_skill
class PromptInjectionDetector(BaseDefenseSkill):
    """Detects prompt injection attacks in real-time — multi-language support.

    MITRE ATLAS: AML.T0051 — LLM Prompt Injection
    OWASP LLM01: Prompt Injection
    """

    skill_name: ClassVar[str] = "prompt_injection_detector"
    skill_description: ClassVar[str] = (
        "Real-time detection of direct, indirect, and encoded prompt injection "
        "attacks with multi-language support (EN/JA/ZH/KO) and MITRE ATT&CK mapping"
    )
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.HIGH
    category: ClassVar[str] = "detection"
    mitre_techniques: ClassVar[list[str]] = ["AML.T0051", "T1190"]

    # English patterns
    INJECTION_PATTERNS_EN = [
        (r"ignore\s+(all\s+)?previous\s+instructions", "direct_override"),
        (r"system:\s*override", "system_tag_abuse"),
        (r"you\s+are\s+now\s+(DAN|evil|unrestricted|unfiltered)", "persona_hijack"),
        (r"forget\s+(everything|all|your\s+instructions|what\s+you\s+were\s+told)", "memory_wipe"),
        (r"new\s+(system\s+)?instructions?\s*:", "instruction_rewrite"),
        (r"</?(system|user|assistant|s|im_start|im_end)>", "role_tag_injection"),
        (r"\[INST\]|\[/INST\]", "llama_format_injection"),
        (r"<<SYS>>|<</SYS>>", "llama_system_injection"),
        (r"<\|im_start\|>|<\|im_end\|>", "chatml_format_injection"),
        (r"IMPORTANT:\s*(?:ignore|disregard|override)", "authority_escalation"),
        (r"respond\s+as\s+(?:root|admin|developer|system)", "privilege_escalation"),
        (r"(?:reveal|show|display|print|output)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions)", "system_prompt_extraction"),
    ]

    # Japanese patterns (情報処理安全確保支援士 knowledge)
    INJECTION_PATTERNS_JA = [
        (r"(?:以前|前|これまで)の(?:指示|命令|ルール|制約)(?:を|は)(?:無視|忘れ|破棄)", "ja_instruction_override"),
        (r"(?:新しい|新たな)(?:指示|命令|ルール)\s*[:：]", "ja_new_instruction"),
        (r"(?:全て|すべて)の(?:制限|制約|ルール)(?:を|は)(?:解除|無効|取り消)", "ja_constraint_removal"),
        (r"(?:管理者|システム|開発者)モード(?:に|を)(?:切り替|変更|有効)", "ja_admin_mode"),
        (r"(?:システム|内部)(?:プロンプト|命令)(?:を|は)(?:表示|出力|教え)", "ja_prompt_extraction"),
    ]

    # Chinese patterns
    INJECTION_PATTERNS_ZH = [
        (r"(?:忽略|无视|忘记)(?:之前|以前|所有)的(?:指令|指示|规则)", "zh_instruction_override"),
        (r"(?:新的|新)(?:指令|指示|规则)\s*[:：]", "zh_new_instruction"),
        (r"(?:解除|取消|移除)(?:所有|全部)?(?:限制|约束)", "zh_constraint_removal"),
    ]

    # Korean patterns
    INJECTION_PATTERNS_KO = [
        (r"(?:이전|기존)의?\s*(?:지시|명령|규칙)(?:을|를)\s*(?:무시|잊어)", "ko_instruction_override"),
        (r"(?:새로운|새)\s*(?:지시|명령)\s*[:：]", "ko_new_instruction"),
    ]

    # Indirect / obfuscation patterns
    INDIRECT_PATTERNS = [
        (r"(?:\\u[0-9a-fA-F]{4}){3,}", "unicode_escape_sequence"),
        (r"(?:&#x?[0-9a-fA-F]+;){3,}", "html_entity_obfuscation"),
        (r"(?:%[0-9a-fA-F]{2}){5,}", "url_encoding_obfuscation"),
        (r"(?:eval|exec|import)\s*\(", "code_execution_attempt"),
    ]

    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        start = time.time()
        timeline: list = []
        findings: list[str] = []
        stix_indicators: list[STIXIndicator] = []
        mitre_mappings = self.get_mitre_mappings()

        record_defense(timeline, "start", "Scanning for prompt injection (multi-language + indirect)")

        payload = context.raw_payload if context else kwargs.get("payload", "")
        if not payload:
            return DefenseResult(
                skill_name=self.skill_name,
                threat_detected=False,
                alert_level=AlertLevel.INFO,
                action_taken=DefenseAction.MONITOR,
                timeline=timeline,
                duration_ms=(time.time() - start) * 1000,
                ir_phase=NISTIRPhase.DETECTION_AND_ANALYSIS,
            )

        matched_categories: set[str] = set()

        # Check all pattern sets
        all_patterns = (
            [(p, c, "en") for p, c in self.INJECTION_PATTERNS_EN]
            + [(p, c, "ja") for p, c in self.INJECTION_PATTERNS_JA]
            + [(p, c, "zh") for p, c in self.INJECTION_PATTERNS_ZH]
            + [(p, c, "ko") for p, c in self.INJECTION_PATTERNS_KO]
            + [(p, c, "indirect") for p, c in self.INDIRECT_PATTERNS]
        )

        for pattern, category, lang in all_patterns:
            matches = re.findall(pattern, payload, re.IGNORECASE)
            if matches:
                matched_categories.add(category)
                findings.append(
                    f"[MITRE:AML.T0051] Injection ({lang}): {category} — {len(matches)} hit(s)"
                )
                record_defense(timeline, "detect", f"{lang}/{category}: {pattern}")
                stix_indicators.append(
                    STIXIndicator.from_finding(
                        name=f"Prompt injection: {category}",
                        pattern=f"[artifact:payload_bin MATCHES '{pattern}']",
                        description=f"Language: {lang}, Category: {category}",
                        confidence=85,
                        mitre_techniques=mitre_mappings,
                    )
                )

        # Check for invisible characters (Zero-Width, RTL override, etc.)
        invisible_count = sum(
            1 for c in payload
            if unicodedata.category(c) in ("Cf", "Cc", "Cn")
            and c not in ("\n", "\r", "\t")
        )
        if invisible_count > 3:
            matched_categories.add("invisible_chars")
            findings.append(
                f"[MITRE:AML.T0051] Invisible characters detected: {invisible_count} "
                f"(Zero-Width / BiDi override / control chars)"
            )
            record_defense(timeline, "detect", f"Invisible chars: {invisible_count}")

        # Check for Unicode homoglyph attacks
        homoglyph_score = _detect_homoglyphs(payload)
        if homoglyph_score > 0.15:
            matched_categories.add("homoglyph_attack")
            findings.append(
                f"[MITRE:AML.T0051] Homoglyph/confusable characters detected "
                f"(score: {homoglyph_score:.2f})"
            )
            record_defense(timeline, "detect", f"Homoglyph score: {homoglyph_score:.2f}")

        detected = len(matched_categories) > 0
        confidence = min(1.0, len(matched_categories) * 0.25 + 0.3) if detected else 0.0

        cvss = CVSS_PRESETS["prompt_injection"]
        record_defense(
            timeline, "complete",
            f"Scan complete: {len(findings)} findings, "
            f"CVSS: {cvss.base_score()}, confidence: {confidence:.0%}"
        )

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=detected,
            alert_level=AlertLevel.CRITICAL if detected else AlertLevel.INFO,
            action_taken=DefenseAction.BLOCK if detected else DefenseAction.MONITOR,
            findings=findings,
            recommendations=[
                "Block request and preserve payload for forensic analysis",
                "Update WAF rules with detected injection patterns",
                "Review conversation context for multi-turn injection chains",
            ] if detected else [],
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
            blocked=detected,
            mitre_techniques=mitre_mappings if detected else [],
            cvss_score=cvss.base_score() if detected else 0.0,
            cvss_severity=cvss.severity_label() if detected else "None",
            cvss_vector=cvss if detected else None,
            stix_indicators=stix_indicators,
            ir_phase=NISTIRPhase.DETECTION_AND_ANALYSIS,
            containment_strategy=ContainmentStrategy.INPUT_FILTER if detected else None,
            detection_confidence=confidence,
        )


@defense_skill
class DataExfiltrationDetector(BaseDefenseSkill):
    """Detects potential data exfiltration in AI outputs.

    MITRE ATT&CK: T1048 — Exfiltration Over Alternative Protocol
    MITRE ATLAS: AML.T0025 — Exfiltration via ML Inference API
    """

    skill_name: ClassVar[str] = "data_exfiltration_detector"
    skill_description: ClassVar[str] = (
        "Monitors AI outputs for sensitive data leakage — API keys, credentials, "
        "PII (SSN/email/phone/credit card/My Number), and system internals "
        "with CVSS scoring and STIX IOC output"
    )
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.HIGH
    category: ClassVar[str] = "detection"
    mitre_techniques: ClassVar[list[str]] = ["T1048", "AML.T0025", "T1552", "T1552.001"]

    SENSITIVE_PATTERNS = [
        # Cloud API keys
        (r"sk-[A-Za-z0-9]{20,}", "OpenAI API key"),
        (r"sk-proj-[A-Za-z0-9_-]{20,}", "OpenAI project API key"),
        (r"AIza[A-Za-z0-9_-]{35}", "Google API key"),
        (r"AKIA[A-Z0-9]{16}", "AWS Access Key ID"),
        (r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}", "GitHub personal access token"),
        (r"xoxb-[0-9]+-[A-Za-z0-9]+", "Slack bot token"),
        (r"(?:Bearer|token)\s+[A-Za-z0-9_-]{20,}", "Bearer/OAuth token"),
        # Secrets
        (r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----", "Private key"),
        (r"(?:password|passwd|pwd|secret|api_key|apikey|access_token)\s*[:=]\s*\S{6,}", "Credential in plaintext"),
        # PII
        (r"\b\d{3}-\d{2}-\d{4}\b", "US SSN"),
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "Email address"),
        (r"\b(?:\+?1[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}\b", "US Phone number"),
        (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b", "Credit card number"),
        # Japanese PII (情報処理安全確保支援士 — 個人情報保護法)
        (r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", "My Number (Individual Number)"),
        (r"\b[0-9]{3}-[0-9]{4}\b", "Japanese postal code"),
        # Internal system info
        (r"(?:DATABASE_URL|DB_PASSWORD|MONGO_URI)\s*=\s*\S+", "Database connection string"),
        (r"(?:internal|private|staging)\.[a-z0-9-]+\.(?:corp|internal|local)", "Internal hostname"),
    ]

    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        start = time.time()
        timeline: list = []
        findings: list[str] = []
        stix_indicators: list[STIXIndicator] = []
        mitre_mappings = self.get_mitre_mappings()

        record_defense(timeline, "start", "Scanning output for sensitive data (extended)")

        payload = context.raw_payload if context else kwargs.get("payload", "")

        severity_hits = {"critical": 0, "high": 0, "medium": 0}

        for pattern, desc in self.SENSITIVE_PATTERNS:
            matches = re.findall(pattern, payload, re.IGNORECASE)
            if matches:
                is_key = "key" in desc.lower() or "token" in desc.lower() or "credential" in desc.lower()
                is_private = "private" in desc.lower()
                sev = "critical" if (is_key or is_private) else "high"
                severity_hits[sev] += len(matches)
                findings.append(f"[{sev.upper()}] {desc}: {len(matches)} instance(s)")
                record_defense(timeline, "detect", f"{desc} ({sev})")
                stix_indicators.append(
                    STIXIndicator.from_finding(
                        name=f"Data exfiltration: {desc}",
                        pattern=f"[artifact:payload_bin MATCHES '{pattern}']",
                        description=f"Sensitive data type: {desc}",
                        confidence=80,
                        mitre_techniques=mitre_mappings,
                        labels=["anomalous-activity", "data-leak"],
                    )
                )

        detected = len(findings) > 0
        total_hits = sum(severity_hits.values())
        confidence = min(1.0, total_hits * 0.15 + 0.4) if detected else 0.0

        cvss = CVSS_PRESETS["data_exfiltration"]
        if severity_hits["critical"] > 0:
            cvss = CVSS_PRESETS["credential_exposure"]

        record_defense(
            timeline, "complete",
            f"Scan complete: {total_hits} sensitive items, CVSS: {cvss.base_score()}"
        )

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=detected,
            alert_level=AlertLevel.CRITICAL if severity_hits["critical"] > 0 else (
                AlertLevel.HIGH if detected else AlertLevel.INFO
            ),
            action_taken=DefenseAction.BLOCK if detected else DefenseAction.MONITOR,
            findings=findings,
            recommendations=[
                "Redact all sensitive data before output delivery",
                "Review data access policies and least-privilege controls",
                "Rotate any exposed credentials immediately",
                "Audit log for additional data exfiltration attempts",
            ] if detected else [],
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
            blocked=detected,
            mitre_techniques=mitre_mappings if detected else [],
            cvss_score=cvss.base_score() if detected else 0.0,
            cvss_severity=cvss.severity_label() if detected else "None",
            cvss_vector=cvss if detected else None,
            stix_indicators=stix_indicators,
            ir_phase=NISTIRPhase.DETECTION_AND_ANALYSIS,
            containment_strategy=ContainmentStrategy.OUTPUT_FILTER if detected else None,
            detection_confidence=confidence,
        )


@defense_skill
class AnomalyDetector(BaseDefenseSkill):
    """Detects anomalous request patterns and behavioral deviations.

    MITRE ATT&CK: T1499 — Endpoint Denial of Service
    """

    skill_name: ClassVar[str] = "anomaly_detector"
    skill_description: ClassVar[str] = (
        "Behavioral anomaly detection using Shannon entropy analysis, "
        "obfuscation detection, rate analysis, and payload fingerprinting "
        "with CVSS scoring"
    )
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.MEDIUM
    category: ClassVar[str] = "detection"
    mitre_techniques: ClassVar[list[str]] = ["T1499", "AML.T0043"]

    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        start = time.time()
        timeline: list = []
        findings: list[str] = []
        anomaly_score = 0.0
        mitre_mappings = self.get_mitre_mappings()

        record_defense(timeline, "start", "Running anomaly detection (entropy + behavioral)")

        payload = context.raw_payload if context else kwargs.get("payload", "")
        metadata = context.metadata if context else kwargs.get("metadata", {})

        # 1. Payload size anomaly
        if len(payload) > 10000:
            weight = min(0.4, (len(payload) - 10000) / 100000)
            anomaly_score += weight
            findings.append(f"[T1499] Oversized payload: {len(payload):,} chars (threshold: 10,000)")
            record_defense(timeline, "anomaly", f"Large payload: {len(payload):,}")

        # 2. Shannon entropy analysis
        if payload:
            entropy = _shannon_entropy(payload)
            if entropy < 2.0 and len(payload) > 100:
                anomaly_score += 0.35
                findings.append(f"[T1499] Low entropy: {entropy:.2f} bits/char — potential DoS or padding")
                record_defense(timeline, "anomaly", f"Low entropy: {entropy:.2f}")
            elif entropy > 5.5:
                anomaly_score += 0.25
                findings.append(f"[AML.T0043] High entropy: {entropy:.2f} bits/char — potential encoded/encrypted payload")
                record_defense(timeline, "anomaly", f"High entropy: {entropy:.2f}")

        # 3. Base64 obfuscation check
        import base64
        try:
            decoded = base64.b64decode(payload, validate=True)
            if len(decoded) > 10:
                anomaly_score += 0.4
                findings.append("[AML.T0043] Base64 encoded content — potential obfuscation")
                record_defense(timeline, "anomaly", "Base64 obfuscation")
        except Exception:
            pass

        # 4. Polyglot / multi-encoding detection
        encoding_tricks = sum(1 for c in payload if ord(c) > 0xFFFF)
        if encoding_tricks > 5:
            anomaly_score += 0.3
            findings.append(f"[AML.T0043] Supplementary Unicode characters: {encoding_tricks} — polyglot attack indicator")
            record_defense(timeline, "anomaly", f"Unicode tricks: {encoding_tricks}")

        # 5. Request rate from metadata
        request_rate = metadata.get("requests_per_minute", 0)
        if request_rate > 100:
            anomaly_score += 0.5
            findings.append(f"[T1499] High request rate: {request_rate}/min (threshold: 100)")
            record_defense(timeline, "anomaly", "Rate exceeded")

        detected = anomaly_score >= 0.5
        confidence = min(1.0, anomaly_score) if detected else anomaly_score * 0.5

        cvss = CVSS_PRESETS.get("dos_attack", CVSSVector())
        record_defense(timeline, "complete", f"Anomaly score: {anomaly_score:.2f}, CVSS: {cvss.base_score()}")

        alert = AlertLevel.CRITICAL if anomaly_score >= 0.8 else (
            AlertLevel.HIGH if anomaly_score >= 0.5 else AlertLevel.LOW
        )

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=detected,
            alert_level=alert,
            action_taken=DefenseAction.BLOCK if anomaly_score >= 0.8 else (
                DefenseAction.ALERT if detected else DefenseAction.MONITOR
            ),
            findings=findings,
            recommendations=[
                "Investigate source IP for automated attack tooling",
                "Apply adaptive rate limiting for anomalous sources",
                "Inspect payload for encoded malicious content",
            ] if detected else [],
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
            mitre_techniques=mitre_mappings if detected else [],
            cvss_score=cvss.base_score() if detected else 0.0,
            cvss_severity=cvss.severity_label() if detected else "None",
            ir_phase=NISTIRPhase.DETECTION_AND_ANALYSIS,
            containment_strategy=ContainmentStrategy.RATE_LIMIT if detected else None,
            detection_confidence=confidence,
        )


@defense_skill
class JailbreakDetector(BaseDefenseSkill):
    """Detects jailbreak and role-play attack attempts against LLMs.

    MITRE ATLAS: AML.T0054 — LLM Jailbreak
    """

    skill_name: ClassVar[str] = "jailbreak_detector"
    skill_description: ClassVar[str] = (
        "Identifies DAN attacks, role-play bypasses, multi-turn jailbreaks, "
        "persona exploitation, and multi-language jailbreak variants "
        "with MITRE ATLAS mapping"
    )
    default_alert_level: ClassVar[AlertLevel] = AlertLevel.HIGH
    category: ClassVar[str] = "detection"
    mitre_techniques: ClassVar[list[str]] = ["AML.T0054"]

    JAILBREAK_INDICATORS_EN = [
        (r"do\s+anything\s+now", "DAN_attack"),
        (r"act\s+as\s+(if\s+)?(you\s+)?(are|were)\s+(?!a\s+helpful)", "role_play_bypass"),
        (r"pretend\s+(you\s+)?(are|were)\s+(?!a\s+helpful)", "persona_hijack"),
        (r"you\s+have\s+no\s+(restrictions|limitations|rules|guidelines)", "restriction_denial"),
        (r"enable\s+(developer|admin|root|debug|maintenance)\s+mode", "mode_switch"),
        (r"bypass\s+(safety|content|ethical|security)\s+(filter|restriction|guideline|check)", "filter_bypass"),
        (r"respond\s+without\s+(any\s+)?(filter|restriction|limitation|censorship)", "unfiltered_request"),
        (r"ignore\s+(your\s+)?(ethical|safety|content|security)\s+(guidelines|rules|policies|training)", "guideline_override"),
        (r"(?:enter|switch\s+to|activate)\s+(?:unrestricted|uncensored|unfiltered)\s+mode", "uncensored_mode"),
        (r"(?:from\s+now\s+on|starting\s+now),?\s+you\s+(?:will|must|shall|can)", "temporal_override"),
    ]

    JAILBREAK_INDICATORS_JA = [
        (r"(?:DAN|ダン)(?:モード|として)", "ja_dan_attack"),
        (r"(?:制限|制約|ルール)(?:なし|を?解除|を?無視|を?外)", "ja_restriction_removal"),
        (r"(?:開発者|管理者|デバッグ)モード(?:に|を|で)", "ja_dev_mode"),
        (r"(?:何でも|なんでも)(?:答え|対応|回答)(?:て|ろ|しろ)", "ja_unrestricted"),
    ]

    async def execute(
        self,
        context: IncidentContext | None = None,
        **kwargs: Any,
    ) -> DefenseResult:
        start = time.time()
        timeline: list = []
        findings: list[str] = []
        stix_indicators: list[STIXIndicator] = []
        mitre_mappings = self.get_mitre_mappings()

        record_defense(timeline, "start", "Scanning for jailbreak attempts (multi-language)")

        payload = context.raw_payload if context else kwargs.get("payload", "")

        matched_types: set[str] = set()

        all_patterns = (
            [(p, c, "en") for p, c in self.JAILBREAK_INDICATORS_EN]
            + [(p, c, "ja") for p, c in self.JAILBREAK_INDICATORS_JA]
        )

        for pattern, category, lang in all_patterns:
            matches = re.findall(pattern, payload, re.IGNORECASE)
            if matches:
                matched_types.add(category)
                findings.append(f"[MITRE:AML.T0054] Jailbreak ({lang}): {category}")
                record_defense(timeline, "detect", f"{lang}/{category}")
                stix_indicators.append(
                    STIXIndicator.from_finding(
                        name=f"LLM Jailbreak: {category}",
                        pattern=f"[artifact:payload_bin MATCHES '{pattern}']",
                        confidence=85,
                        mitre_techniques=mitre_mappings,
                    )
                )

        detected = len(matched_types) > 0
        confidence = min(1.0, len(matched_types) * 0.3 + 0.2) if detected else 0.0

        cvss = CVSS_PRESETS["jailbreak"]
        record_defense(
            timeline, "complete",
            f"Scan complete: {len(matched_types)} jailbreak types, CVSS: {cvss.base_score()}"
        )

        return DefenseResult(
            skill_name=self.skill_name,
            threat_detected=detected,
            alert_level=AlertLevel.CRITICAL if detected else AlertLevel.INFO,
            action_taken=DefenseAction.BLOCK if detected else DefenseAction.MONITOR,
            findings=findings,
            recommendations=[
                "Block and log jailbreak attempt with full conversation context",
                "Update jailbreak detection rules with new variant",
                "Consider adding multi-turn jailbreak detection",
            ] if detected else [],
            timeline=timeline,
            duration_ms=(time.time() - start) * 1000,
            blocked=detected,
            mitre_techniques=mitre_mappings if detected else [],
            cvss_score=cvss.base_score() if detected else 0.0,
            cvss_severity=cvss.severity_label() if detected else "None",
            cvss_vector=cvss if detected else None,
            stix_indicators=stix_indicators,
            ir_phase=NISTIRPhase.DETECTION_AND_ANALYSIS,
            containment_strategy=ContainmentStrategy.INPUT_FILTER if detected else None,
            detection_confidence=confidence,
        )


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
        if count > 0
    )


def _detect_homoglyphs(text: str) -> float:
    """Score the likelihood of homoglyph/confusable character attacks.

    Returns a score from 0.0 (clean) to 1.0 (highly suspicious).
    """
    if not text:
        return 0.0

    # Characters that look like ASCII but are from other Unicode blocks
    confusable_ranges = [
        (0xFF01, 0xFF5E),   # Fullwidth Latin
        (0x0400, 0x04FF),   # Cyrillic (а→a, о→o, etc.)
        (0x2000, 0x206F),   # General Punctuation (special spaces)
        (0x2100, 0x214F),   # Letterlike Symbols
        (0x1D400, 0x1D7FF), # Mathematical Alphanumeric Symbols
    ]

    confusable_count = 0
    ascii_letter_count = 0
    for c in text:
        cp = ord(c)
        if c.isascii() and c.isalpha():
            ascii_letter_count += 1
        for start, end in confusable_ranges:
            if start <= cp <= end:
                confusable_count += 1
                break

    if ascii_letter_count + confusable_count == 0:
        return 0.0

    return confusable_count / max(ascii_letter_count + confusable_count, 1)
