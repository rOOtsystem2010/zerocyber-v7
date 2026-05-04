"""ZeroCyber v7 — Report generators: JSON, SARIF, HTML."""
import json
import os
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass, field, asdict
from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Decision(Enum):
    FIX_NOW = "FIX_NOW"
    FIX_SOON = "FIX_SOON"
    MONITOR = "MONITOR"
    IGNORE = "IGNORE"


@dataclass
class ScanResult:
    metadata: Dict[str, Any]
    system_summary: str
    files_scanned: int
    total_files: int
    coverage_percent: float
    total_loc: int
    languages: Dict[str, int]
    scan_duration: float
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    dependency_vulns: List[Dict[str, Any]] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    executive_summary: str = ""


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "INFO"


class JSONReporter:
    """Generate JSON report."""

    def generate(self, result: ScanResult) -> str:
        return json.dumps(self.to_dict(result), indent=2, default=str)

    def to_dict(self, result: ScanResult) -> Dict[str, Any]:
        return asdict(result)


class SARIFReporter:
    """Generate SARIF v2.1.0 report for GitHub/GitLab/Azure DevOps."""

    def generate(self, result: ScanResult) -> str:
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "ZeroCyber",
                        "version": result.metadata.get("version", "7.0.0"),
                        "informationUri": "https://github.com/zerocyber/zerocyber",
                        "rules": []
                    }
                },
                "results": [],
                "invocations": [{
                    "executionSuccessful": True,
                    "startTimeUtc": result.metadata.get("start_time", datetime.now().isoformat()),
                    "endTimeUtc": datetime.now().isoformat(),
                }],
            }]
        }

        rules_added = set()
        for vuln in result.vulnerabilities:
            rule_id = vuln.get('cwe_id', 'CWE-UNKNOWN')
            if rule_id not in rules_added:
                sarif["runs"][0]["tool"]["driver"]["rules"].append({
                    "id": rule_id,
                    "name": vuln.get('vuln_type', 'Unknown'),
                    "shortDescription": {"text": vuln.get('title', 'Unknown vulnerability')},
                    "fullDescription": {"text": vuln.get('description', 'No description')},
                    "helpUri": f"https://cwe.mitre.org/data/definitions/{rule_id.replace('CWE-', '')}.html",
                    "properties": {
                        "category": vuln.get('owasp_category', 'Unknown'),
                        "cvss": vuln.get('cvss_score', 0),
                    }
                })
                rules_added.add(rule_id)

            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": self._relative_path(vuln.get('file_path', ''), result.metadata.get('project_path', ''))},
                    "region": {
                        "startLine": vuln.get('line_number', 1),
                        "startColumn": 1,
                        "endColumn": 100,
                        "snippet": {"text": vuln.get('code_snippet', '')},
                    }
                }
            }

            sarif_result = {
                "ruleId": rule_id,
                "ruleIndex": list(rules_added).index(rule_id),
                "level": self._severity_to_sarif_level(vuln.get('severity', 'INFO')),
                "message": {"text": vuln.get('description', 'No description')},
                "locations": [location],
                "properties": {
                    "cvss_score": vuln.get('cvss_score', 0),
                    "cvss_vector": vuln.get('cvss_vector', ''),
                    "confidence": vuln.get('confidence', 'LOW'),
                    "taint_path": vuln.get('taint_path', []),
                    "decision": vuln.get('decision', {}).get('decision', 'IGNORE'),
                    "priority_score": vuln.get('decision', {}).get('priority_score', 0),
                    "business_impact": vuln.get('business_impact', {}),
                    "remediation": vuln.get('remediation', {}),
                },
                "fingerprints": {
                    "primary": vuln.get('fingerprint', self._compute_fingerprint(vuln)),
                }
            }
            sarif["runs"][0]["results"].append(sarif_result)

        # Add dependency vulnerabilities
        for dep_vuln in result.dependency_vulns:
            rule_id = dep_vuln.get('cve_id', 'CVE-UNKNOWN')
            if rule_id not in rules_added:
                sarif["runs"][0]["tool"]["driver"]["rules"].append({
                    "id": rule_id,
                    "name": f"{dep_vuln.get('package', 'Unknown')} - {dep_vuln.get('severity', 'Unknown')}",
                    "shortDescription": {"text": dep_vuln.get('description', 'Dependency vulnerability')},
                    "fullDescription": {"text": f"Vulnerable dependency: {dep_vuln.get('package', 'Unknown')}@{dep_vuln.get('current_version', 'unknown')}"},
                    "properties": {"category": "Dependency Vulnerability", "cvss": dep_vuln.get('cvss_score', 0)},
                })
                rules_added.add(rule_id)

            sarif_result = {
                "ruleId": rule_id,
                "ruleIndex": list(rules_added).index(rule_id),
                "level": self._severity_to_sarif_level(dep_vuln.get('severity', 'INFO')),
                "message": {"text": dep_vuln.get('description', 'No description')},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "dependency_manifest"},
                    }
                }],
                "properties": {
                    "package": dep_vuln.get('package', ''),
                    "current_version": dep_vuln.get('current_version', ''),
                    "fixed_version": dep_vuln.get('fixed_version', ''),
                    "severity": dep_vuln.get('severity', ''),
                }
            }
            sarif["runs"][0]["results"].append(sarif_result)

        return json.dumps(sarif, indent=2)

    def _severity_to_sarif_level(self, severity: str) -> str:
        mapping = {
            'CRITICAL': 'error',
            'HIGH': 'error',
            'MEDIUM': 'warning',
            'LOW': 'warning',
            'INFO': 'note',
        }
        return mapping.get(severity.upper(), 'warning')

    def _relative_path(self, full_path: str, project_path: str) -> str:
        try:
            return os.path.relpath(full_path, project_path)
        except Exception:
            return full_path

    def _compute_fingerprint(self, vuln: Dict) -> str:
        content = f"{vuln.get('file_path', '')}:{vuln.get('line_number', 0)}:{vuln.get('vuln_type', '')}"
        import hashlib
        return hashlib.sha256(content.encode()).hexdigest()[:16]


class HTMLReporter:
    """Generate interactive HTML report."""

    def generate(self, result: ScanResult) -> str:
        vulns = result.vulnerabilities
        dep_vulns = result.dependency_vulns

        # Build vulnerability cards
        vuln_cards = ""
        for i, v in enumerate(vulns, 1):
            severity_color = self._severity_color(v.get('severity', 'INFO'))
            decision = v.get('decision', {})
            business = v.get('business_impact', {})
            remediation = v.get('remediation', {})

            taint_path_html = ""
            for step in v.get('taint_path', []):
                taint_path_html += f"<li>{self._escape(step)}</li>"

            attack_chain_html = ""
            for step in v.get('attack_chain', []):
                attack_chain_html += f"""
                <div class="chain-step">
                    <span class="chain-tech">[{self._escape(step.get('technique', ''))}]</span>
                    <span class="chain-desc">{self._escape(step.get('description', ''))}</span>
                    <span class="chain-conf">confidence: {step.get('confidence', 0):.0%}</span>
                </div>
                """

            vuln_cards += f"""
            <div class="vuln-card {severity_color.lower()}">
                <div class="vuln-header">
                    <span class="badge severity-{severity_color.lower()}">{v.get('severity', 'INFO')}</span>
                    <span class="badge confidence-{v.get('confidence', 'LOW').lower()}">{v.get('confidence', 'LOW')}</span>
                    <span class="badge decision-{decision.get('decision', 'IGNORE').lower().replace('_', '-')}">{decision.get('decision', 'IGNORE')}</span>
                    <h3>{i}. {self._escape(v.get('title', 'Unknown'))}</h3>
                </div>
                <div class="vuln-body">
                    <p><strong>Type:</strong> {self._escape(v.get('vuln_type', 'Unknown'))}</p>
                    <p><strong>CWE:</strong> {v.get('cwe_id', 'N/A')} | <strong>CVSS:</strong> {v.get('cvss_score', 0)}</p>
                    <p><strong>Location:</strong> <code>{self._escape(v.get('file_path', ''))}:{v.get('line_number', 0)}</code></p>
                    <p><strong>Function:</strong> <code>{self._escape(v.get('function_name', ''))}</code></p>
                    <p><strong>Description:</strong> {self._escape(v.get('description', ''))}</p>

                    <div class="section">
                        <h4>🔍 Taint Path</h4>
                        <ol>{taint_path_html}</ol>
                    </div>

                    <div class="section">
                        <h4>⚔️ Attack Chain</h4>
                        {attack_chain_html}
                    </div>

                    <div class="section">
                        <h4>💰 Business Impact</h4>
                        <ul>
                            <li><strong>Financial Loss:</strong> {business.get('financial_loss_estimate', 'N/A')}</li>
                            <li><strong>Users Affected:</strong> {business.get('users_affected_estimate', 0):,}</li>
                            <li><strong>Reputation Risk:</strong> {business.get('reputation_risk', 'N/A')}</li>
                            <li><strong>Compliance:</strong> {', '.join(business.get('compliance_risk', []))}</li>
                        </ul>
                    </div>

                    <div class="section">
                        <h4>🛠️ Remediation</h4>
                        <p><strong>Technical Fix:</strong> {self._escape(remediation.get('technical_fix', 'N/A'))}</p>
                        <p><strong>Executive Action:</strong> {self._escape(remediation.get('executive_action', 'N/A'))}</p>
                        <p><strong>Timeline:</strong> {decision.get('timeline', 'N/A')}</p>
                    </div>

                    <div class="section">
                        <h4>🎯 Decision</h4>
                        <p><strong>Priority Score:</strong> {decision.get('priority_score', 0):.2f}</p>
                        <p><strong>Technical Action:</strong> {self._escape(decision.get('technical_action', 'N/A'))}</p>
                        <p><strong>Executive Action:</strong> {self._escape(decision.get('executive_action', 'N/A'))}</p>
                        <p><strong>Resources:</strong> {', '.join(decision.get('resources_needed', []))}</p>
                    </div>
                </div>
            </div>
            """

        # Dependency vulnerability cards
        dep_cards = ""
        for dep in dep_vulns:
            severity_color = self._severity_color(dep.get('severity', 'INFO'))
            dep_cards += f"""
            <div class="vuln-card dep-card {severity_color.lower()}">
                <div class="vuln-header">
                    <span class="badge severity-{severity_color.lower()}">{dep.get('severity', 'INFO')}</span>
                    <span class="badge ecosystem">{dep.get('ecosystem', 'unknown')}</span>
                    <h3>📦 {self._escape(dep.get('package', 'Unknown'))} @ {self._escape(dep.get('current_version', 'unknown'))}</h3>
                </div>
                <div class="vuln-body">
                    <p><strong>CVE:</strong> <code>{dep.get('cve_id', 'N/A')}</code></p>
                    <p><strong>Fixed Version:</strong> {self._escape(dep.get('fixed_version', 'N/A'))}</p>
                    <p><strong>Description:</strong> {self._escape(dep.get('description', ''))}</p>
                </div>
            </div>
            """

        # Statistics
        stats = result.statistics
        severity_breakdown = stats.get('severity_breakdown', {})
        decision_breakdown = stats.get('decision_breakdown', {})

        severity_bars = ""
        for sev, count in severity_breakdown.items():
            color = self._severity_color(sev)
            max_val = max(severity_breakdown.values()) if severity_breakdown else 1
            width = (count / max_val * 100) if max_val > 0 else 0
            severity_bars += f"""
            <div class="bar-container">
                <span class="bar-label">{sev}</span>
                <div class="bar" style="width: {width}%; background: {color};"></div>
                <span class="bar-value">{count}</span>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZeroCyber v7 Security Report</title>
    <style>
        :root {{
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #17a2b8;
            --info: #6c757d;
            --bg: #f8f9fa;
            --card-bg: #ffffff;
            --text: #212529;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
        }}
        header h1 {{
            margin: 0;
            font-size: 2.5rem;
        }}
        header p {{
            margin: 10px 0 0;
            opacity: 0.9;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: var(--card-bg);
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .stat-card h3 {{
            margin: 0 0 10px;
            font-size: 0.9rem;
            text-transform: uppercase;
            color: #666;
        }}
        .stat-card .value {{
            font-size: 2rem;
            font-weight: bold;
            color: var(--text);
        }}
        .filters {{
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }}
        .filter-btn {{
            padding: 8px 16px;
            border: none;
            border-radius: 4px;
            background: var(--card-bg);
            cursor: pointer;
            font-size: 0.9rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .filter-btn.active {{
            background: #1a1a2e;
            color: white;
        }}
        .vuln-card {{
            background: var(--card-bg);
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            overflow: hidden;
            border-left: 5px solid var(--info);
        }}
        .vuln-card.critical {{ border-left-color: var(--critical); }}
        .vuln-card.high {{ border-left-color: var(--high); }}
        .vuln-card.medium {{ border-left-color: var(--medium); }}
        .vuln-card.low {{ border-left-color: var(--low); }}
        .vuln-card.info {{ border-left-color: var(--info); }}
        .vuln-header {{
            padding: 20px;
            border-bottom: 1px solid #eee;
        }}
        .vuln-header h3 {{
            margin: 10px 0 0;
            font-size: 1.3rem;
        }}
        .vuln-body {{
            padding: 20px;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
            margin-right: 8px;
            margin-bottom: 5px;
        }}
        .severity-critical {{ background: var(--critical); color: white; }}
        .severity-high {{ background: var(--high); color: white; }}
        .severity-medium {{ background: var(--medium); color: #333; }}
        .severity-low {{ background: var(--low); color: white; }}
        .severity-info {{ background: var(--info); color: white; }}
        .confidence-high {{ background: #28a745; color: white; }}
        .confidence-medium {{ background: #6c757d; color: white; }}
        .confidence-low {{ background: #adb5bd; color: #333; }}
        .decision-fix-now {{ background: var(--critical); color: white; }}
        .decision-fix-soon {{ background: var(--high); color: white; }}
        .decision-monitor {{ background: var(--medium); color: #333; }}
        .decision-ignore {{ background: var(--info); color: white; }}
        .section {{
            margin-top: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 6px;
        }}
        .section h4 {{
            margin: 0 0 10px;
            color: #495057;
        }}
        code {{
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9rem;
        }}
        .chain-step {{
            padding: 8px;
            margin: 4px 0;
            background: white;
            border-radius: 4px;
            border: 1px solid #dee2e6;
        }}
        .chain-tech {{
            font-weight: bold;
            color: #1a1a2e;
        }}
        .chain-conf {{
            float: right;
            color: #6c757d;
            font-size: 0.85rem;
        }}
        .bar-container {{
            display: flex;
            align-items: center;
            margin: 8px 0;
        }}
        .bar-label {{
            width: 80px;
            font-weight: bold;
        }}
        .bar {{
            height: 20px;
            border-radius: 3px;
            margin: 0 10px;
            min-width: 5px;
        }}
        .bar-value {{
            font-weight: bold;
        }}
        .dep-card {{
            border-left-color: #6f42c1;
        }}
        .ecosystem {{
            background: #6f42c1;
            color: white;
        }}
        @media (max-width: 768px) {{
            .stats-grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ ZeroCyber v7 Security Report</h1>
            <p>{self._escape(result.system_summary)}</p>
            <p>Generated: {result.metadata.get('generated_at', datetime.now().isoformat())} | Duration: {result.scan_duration:.2f}s</p>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <h3>Files Scanned</h3>
                <div class="value">{result.files_scanned:,} / {result.total_files:,}</div>
                <small>{result.coverage_percent:.1f}% coverage</small>
            </div>
            <div class="stat-card">
                <h3>Total Vulnerabilities</h3>
                <div class="value">{len(vulns)}</div>
            </div>
            <div class="stat-card">
                <h3>Dependency Vulns</h3>
                <div class="value">{len(dep_vulns)}</div>
            </div>
            <div class="stat-card">
                <h3>Lines of Code</h3>
                <div class="value">{result.total_loc:,}</div>
            </div>
        </div>

        <h2>📊 Severity Breakdown</h2>
        <div class="severity-bars">
            {severity_bars}
        </div>

        <h2>🔴 Source Code Vulnerabilities ({len(vulns)})</h2>
        <div class="vulnerabilities">
            {vuln_cards if vulns else '<p>No vulnerabilities detected.</p>'}
        </div>

        <h2>📦 Dependency Vulnerabilities ({len(dep_vulns)})</h2>
        <div class="dependencies">
            {dep_cards if dep_vulns else '<p>No vulnerable dependencies detected.</p>'}
        </div>

        <footer style="margin-top: 40px; padding: 20px; text-align: center; color: #666;">
            <p>ZeroCyber v7 — AI-Powered Security Analysis | Standards: CWE, CVSS v3.1, OWASP Top 10 2026, CAPEC, NIST SP 800-53</p>
        </footer>
    </div>

    <script>
        // Simple filtering
        const filterButtons = document.querySelectorAll('.filter-btn');
        filterButtons.forEach(btn => {{
            btn.addEventListener('click', () => {{
                const filter = btn.dataset.filter;
                document.querySelectorAll('.vuln-card').forEach(card => {{
                    if (filter === 'all' || card.classList.contains(filter.toLowerCase())) {{
                        card.style.display = 'block';
                    }} else {{
                        card.style.display = 'none';
                    }}
                }});
                filterButtons.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
            }});
        }});
    </script>
</body>
</html>
"""
        return html

    def _severity_color(self, severity: str) -> str:
        colors = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#17a2b8',
            'INFO': '#6c757d',
        }
        return colors.get(severity.upper(), '#6c757d')

    def _escape(self, text: str) -> str:
        return (str(text)
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;'))
