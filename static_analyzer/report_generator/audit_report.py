"""Security Audit Report Generator (PDF/JSON)."""

import json
from datetime import datetime
from typing import Optional
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from static_analyzer.vulnerability_scanner.ai_app_scanner import SecurityAuditResult, Vulnerability
from shared.utils import get_logger

logger = get_logger(__name__)


class SecurityAuditReportGenerator:
    """セキュリティ監査レポートジェネレーター."""

    def __init__(self):
        """レポートジェネレーターの初期化."""
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self) -> None:
        """カスタムスタイルのセットアップ."""
        # タイトルスタイル
        self.title_style = ParagraphStyle(
            "CustomTitle",
            parent=self.styles["Heading1"],
            fontSize=24,
            textColor=colors.HexColor("#1a237e"),
            spaceAfter=30,
            alignment=TA_CENTER,
        )

        # 見出しスタイル
        self.heading_style = ParagraphStyle(
            "CustomHeading",
            parent=self.styles["Heading2"],
            fontSize=16,
            textColor=colors.HexColor("#283593"),
            spaceBefore=20,
            spaceAfter=12,
        )

        # 本文スタイル
        self.body_style = ParagraphStyle(
            "CustomBody",
            parent=self.styles["Normal"],
            fontSize=10,
            leading=14,
        )

    def generate_json_report(
        self,
        audit_result: SecurityAuditResult,
        output_path: Optional[Path] = None,
    ) -> str:
        """
        JSON形式のレポートを生成.

        Args:
            audit_result: 監査結果
            output_path: 出力先パス（Noneの場合はJSON文字列を返す）

        Returns:
            JSON文字列
        """
        logger.info("Generating JSON report")

        # データクラスを辞書に変換
        report_data = {
            "repository_url": audit_result.repository_url,
            "scan_timestamp": audit_result.scan_timestamp,
            "overall_score": audit_result.overall_score,
            "risk_summary": audit_result.risk_summary,
            "recommendations": audit_result.recommendations,
            "auto_fix_available": audit_result.auto_fix_available,
            "vulnerabilities": [
                {
                    "vuln_id": v.vuln_id,
                    "type": v.type.value,
                    "severity": v.severity.value,
                    "title": v.title,
                    "description": v.description,
                    "affected_files": v.affected_files,
                    "code_snippet": v.code_snippet,
                    "remediation": v.remediation,
                    "cwe_id": v.cwe_id,
                    "confidence": v.confidence,
                }
                for v in audit_result.vulnerabilities
            ],
        }

        json_str = json.dumps(report_data, indent=2, ensure_ascii=False)

        if output_path:
            output_path.write_text(json_str, encoding="utf-8")
            logger.info("JSON report saved", output_path=str(output_path))

        return json_str

    def generate_pdf_report(
        self,
        audit_result: SecurityAuditResult,
        output_path: Path,
    ) -> None:
        """
        PDF形式のレポートを生成.

        Args:
            audit_result: 監査結果
            output_path: 出力先パス
        """
        logger.info("Generating PDF report", output_path=str(output_path))

        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18,
        )

        story = []

        # タイトル
        story.append(Paragraph("AegisFlow AI", self.title_style))
        story.append(Paragraph("Security Audit Report", self.title_style))
        story.append(Spacer(1, 0.5 * inch))

        # サマリー情報
        story.append(Paragraph("Executive Summary", self.heading_style))

        summary_data = [
            ["Repository", audit_result.repository_url],
            ["Scan Date", audit_result.scan_timestamp],
            [
                "Overall Security Score",
                f"{audit_result.overall_score:.1f}/100",
            ],
        ]

        summary_table = Table(summary_data, colWidths=[2 * inch, 4 * inch])
        summary_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8eaf6")),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                    ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                ]
            )
        )
        story.append(summary_table)
        story.append(Spacer(1, 0.3 * inch))

        # リスクサマリー
        story.append(Paragraph("Risk Summary", self.heading_style))

        risk_data = [
            ["Severity", "Count"],
            ["Critical", str(audit_result.risk_summary.get("critical", 0))],
            ["High", str(audit_result.risk_summary.get("high", 0))],
            ["Medium", str(audit_result.risk_summary.get("medium", 0))],
            ["Low", str(audit_result.risk_summary.get("low", 0))],
        ]

        risk_table = Table(risk_data, colWidths=[3 * inch, 3 * inch])
        risk_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3f51b5")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 12),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ]
            )
        )
        story.append(risk_table)
        story.append(PageBreak())

        # 脆弱性詳細
        story.append(Paragraph("Vulnerability Details", self.heading_style))

        for i, vuln in enumerate(audit_result.vulnerabilities, 1):
            # 脆弱性タイトル
            vuln_title = f"{i}. [{vuln.severity.value.upper()}] {vuln.title}"
            story.append(Paragraph(vuln_title, self.heading_style))

            # 詳細
            details = [
                ["ID", vuln.vuln_id],
                ["Type", vuln.type.value],
                ["Severity", vuln.severity.value.upper()],
                ["Confidence", f"{vuln.confidence:.0%}"],
                ["Affected Files", ", ".join(vuln.affected_files)],
            ]

            if vuln.cwe_id:
                details.append(["CWE", vuln.cwe_id])

            detail_table = Table(details, colWidths=[1.5 * inch, 4.5 * inch])
            detail_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f5f5f5")),
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                    ]
                )
            )
            story.append(detail_table)
            story.append(Spacer(1, 0.1 * inch))

            # 説明
            story.append(Paragraph("<b>Description:</b>", self.body_style))
            story.append(Paragraph(vuln.description, self.body_style))
            story.append(Spacer(1, 0.1 * inch))

            # 修正方法
            story.append(Paragraph("<b>Remediation:</b>", self.body_style))
            remediation_lines = vuln.remediation.split("\n")
            for line in remediation_lines:
                if line.strip():
                    story.append(Paragraph(line, self.body_style))
            story.append(Spacer(1, 0.3 * inch))

        # 推奨事項
        story.append(PageBreak())
        story.append(Paragraph("Recommendations", self.heading_style))

        for i, rec in enumerate(audit_result.recommendations, 1):
            story.append(Paragraph(f"{i}. {rec}", self.body_style))
            story.append(Spacer(1, 0.1 * inch))

        # フッター
        story.append(Spacer(1, 0.5 * inch))
        footer_text = (
            f"Report generated by AegisFlow AI on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )
        story.append(
            Paragraph(
                footer_text,
                ParagraphStyle(
                    "Footer",
                    parent=self.body_style,
                    fontSize=8,
                    textColor=colors.grey,
                    alignment=TA_CENTER,
                ),
            )
        )

        # PDFビルド
        doc.build(story)
        logger.info("PDF report generated successfully", output_path=str(output_path))

    def generate_html_summary(self, audit_result: SecurityAuditResult) -> str:
        """
        HTML形式のサマリーを生成（GitHub PR用）.

        Args:
            audit_result: 監査結果

        Returns:
            HTML文字列
        """
        logger.info("Generating HTML summary")

        # スコアに基づいて色を決定
        if audit_result.overall_score >= 80:
            score_color = "green"
            score_emoji = "✅"
        elif audit_result.overall_score >= 60:
            score_color = "orange"
            score_emoji = "⚠️"
        else:
            score_color = "red"
            score_emoji = "❌"

        html = f"""
## 🛡️ AegisFlow AI Security Audit Report

### {score_emoji} Overall Security Score: <span style="color: {score_color};">{audit_result.overall_score:.1f}/100</span>

### 📊 Risk Summary
| Severity | Count |
|----------|-------|
| 🔴 Critical | {audit_result.risk_summary.get('critical', 0)} |
| 🟠 High | {audit_result.risk_summary.get('high', 0)} |
| 🟡 Medium | {audit_result.risk_summary.get('medium', 0)} |
| 🟢 Low | {audit_result.risk_summary.get('low', 0)} |

### 🔍 Vulnerabilities Found

"""

        for i, vuln in enumerate(audit_result.vulnerabilities, 1):
            severity_emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢",
            }.get(vuln.severity.value, "⚪")

            html += f"""
#### {i}. {severity_emoji} {vuln.title}

**Severity:** {vuln.severity.value.upper()}
**Type:** {vuln.type.value}
**Confidence:** {vuln.confidence:.0%}
**Affected Files:** {', '.join(f'`{f}`' for f in vuln.affected_files)}

**Description:**
{vuln.description}

**Remediation:**
```
{vuln.remediation}
```

---

"""

        html += f"""
### 💡 Recommendations

"""
        for i, rec in enumerate(audit_result.recommendations, 1):
            html += f"{i}. {rec}\n"

        html += f"""
---

*Report generated by AegisFlow AI on {audit_result.scan_timestamp}*
"""

        return html
