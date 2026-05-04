"""ZeroCyber v7 — Business impact assessment and decision engine."""
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class Decision(Enum):
    FIX_NOW = "FIX_NOW"
    FIX_SOON = "FIX_SOON"
    MONITOR = "MONITOR"
    IGNORE = "IGNORE"


@dataclass
class AssetClassification:
    name: str
    asset_type: str  # 'authentication', 'payment', 'pii', 'api_key', 'data', 'infrastructure'
    value: float  # 0-10
    exposure: str  # 'public', 'internal', 'private'


@dataclass
class BusinessImpact:
    financial_loss_estimate: str
    users_affected_estimate: int
    systems_affected: List[str]
    reputation_risk: str  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    compliance_risk: List[str]
    operational_downtime: str
    data_breach_risk: str


@dataclass
class DecisionResult:
    decision: Decision
    priority_score: float
    technical_action: str
    executive_action: str
    timeline: str
    resources_needed: List[str]
    justification: str


class BusinessEngine:
    """Compute business impact and make prioritization decisions."""

    # Asset type base values
    ASSET_VALUES = {
        'authentication': 9.0,
        'payment': 10.0,
        'pii': 8.5,
        'api_key': 7.0,
        'data': 6.0,
        'infrastructure': 5.0,
        'default': 5.0,
    }

    # Vulnerability type impact multipliers
    VULN_IMPACT = {
        'Command Injection': {'financial': '$2M-$10M', 'users': 500000, 'reputation': 'CRITICAL', 'compliance': ['PCI-DSS', 'SOC2', 'GDPR'], 'downtime': '24-72 hours'},
        'SQL Injection': {'financial': '$1M-$8M', 'users': 300000, 'reputation': 'HIGH', 'compliance': ['PCI-DSS', 'GDPR', 'HIPAA'], 'downtime': '12-48 hours'},
        'Insecure Deserialization': {'financial': '$1M-$8M', 'users': 300000, 'reputation': 'CRITICAL', 'compliance': ['GDPR', 'PCI-DSS', 'SOC2'], 'downtime': '24-72 hours'},
        'SSRF': {'financial': '$500K-$2M', 'users': 100000, 'reputation': 'HIGH', 'compliance': ['SOC2'], 'downtime': '4-24 hours'},
        'Path Traversal': {'financial': '$100K-$1M', 'users': 50000, 'reputation': 'MEDIUM', 'compliance': ['GDPR'], 'downtime': '2-12 hours'},
        'XSS': {'financial': '$100K-$500K', 'users': 200000, 'reputation': 'MEDIUM', 'compliance': ['PCI-DSS'], 'downtime': '1-4 hours'},
        'Code Injection': {'financial': '$2M-$10M', 'users': 500000, 'reputation': 'CRITICAL', 'compliance': ['PCI-DSS', 'SOC2', 'GDPR'], 'downtime': '24-72 hours'},
        'Hardcoded Secret': {'financial': '$500K-$2M', 'users': 100000, 'reputation': 'HIGH', 'compliance': ['PCI-DSS', 'SOC2'], 'downtime': '4-24 hours'},
        'Authentication Bypass': {'financial': '$1M-$5M', 'users': 400000, 'reputation': 'CRITICAL', 'compliance': ['PCI-DSS', 'SOC2', 'GDPR'], 'downtime': '12-48 hours'},
        'IDOR': {'financial': '$500K-$2M', 'users': 150000, 'reputation': 'HIGH', 'compliance': ['GDPR', 'HIPAA'], 'downtime': '4-24 hours'},
        'Prototype Pollution': {'financial': '$100K-$1M', 'users': 50000, 'reputation': 'MEDIUM', 'compliance': ['SOC2'], 'downtime': '2-12 hours'},
        'Open Redirect': {'financial': '$50K-$200K', 'users': 30000, 'reputation': 'LOW', 'compliance': ['PCI-DSS'], 'downtime': '1-4 hours'},
        'Information Disclosure': {'financial': '$200K-$1M', 'users': 80000, 'reputation': 'MEDIUM', 'compliance': ['GDPR'], 'downtime': '2-8 hours'},
        'default': {'financial': '$100K-$500K', 'users': 50000, 'reputation': 'MEDIUM', 'compliance': ['SOC2'], 'downtime': '2-8 hours'},
    }

    def analyze(self, vuln_type: str, source_type: str, confidence: str,
                risk_score: float, has_sanitization: bool = False,
                assets: List[AssetClassification] = None) -> BusinessImpact:
        """Compute business impact for a vulnerability."""
        impact = self.VULN_IMPACT.get(vuln_type, self.VULN_IMPACT['default'])

        # Adjust based on assets
        if assets:
            max_asset_value = max((a.value for a in assets), default=5.0)
            asset_types = [a.asset_type for a in assets]
        else:
            max_asset_value = 5.0
            asset_types = []

        # Financial adjustment
        financial = impact['financial']
        if max_asset_value >= 9:
            financial = financial.replace('$', '$$$').replace('K', 'M').replace('M', 'M')
            # Simple escalation
            if '-' in financial:
                parts = financial.split('-')
                financial = f"${parts[0].replace('$', '').strip()}M-$20M"

        # Users affected
        users = impact['users']
        if max_asset_value >= 8:
            users = int(users * 1.5)

        # Reputation
        reputation = impact['reputation']
        if 'payment' in asset_types or 'authentication' in asset_types:
            reputation = 'CRITICAL'

        # Compliance
        compliance = impact['compliance']
        if 'pii' in asset_types and 'GDPR' not in compliance:
            compliance = compliance + ['GDPR']
        if 'payment' in asset_types and 'PCI-DSS' not in compliance:
            compliance = compliance + ['PCI-DSS']

        return BusinessImpact(
            financial_loss_estimate=financial,
            users_affected_estimate=users,
            systems_affected=['Web Server', 'Application Server', 'Database'],
            reputation_risk=reputation,
            compliance_risk=compliance,
            operational_downtime=impact['downtime'],
            data_breach_risk='HIGH' if 'pii' in asset_types or 'data' in asset_types else 'MEDIUM',
        )

    def make_decision(self, vuln_type: str, confidence: str, risk_score: float,
                      has_sanitization: bool, is_test_file: bool,
                      source_type: str, cvss_score: float,
                      business_impact: BusinessImpact) -> DecisionResult:
        """Make a prioritization decision."""

        # Decision matrix
        score = risk_score

        # Adjust based on CVSS
        if cvss_score >= 9.0:
            score += 0.3
        elif cvss_score >= 7.0:
            score += 0.2

        # Adjust based on business impact
        if business_impact.reputation_risk == 'CRITICAL':
            score += 0.2
        if 'CRITICAL' in business_impact.data_breach_risk or 'HIGH' in business_impact.data_breach_risk:
            score += 0.1
        if business_impact.users_affected_estimate > 100000:
            score += 0.1

        # Confidence boost
        if confidence == 'HIGH':
            score += 0.1
        elif confidence == 'LOW':
            score -= 0.2

        # Penalties
        if has_sanitization:
            score -= 0.3
        if is_test_file:
            score -= 0.5
        if source_type != 'EXTERNAL':
            score -= 0.2

        score = max(0.0, min(1.0, score))

        # Map to decision
        if score >= 0.7:
            decision = Decision.FIX_NOW
            technical_action = f"Immediately patch {vuln_type}. Deploy emergency fix."
            executive_action = f"Escalate to CISO. Consider disabling affected functionality. Notify stakeholders."
            timeline = "24-48 hours"
            resources = ["Senior Security Engineer", "DevOps Lead", "QA Verification"]
            justification = f"Critical risk score {score:.2f}: {vuln_type} with {confidence} confidence, CVSS {cvss_score}, external source."
        elif score >= 0.4:
            decision = Decision.FIX_SOON
            technical_action = f"Schedule {vuln_type} fix in next sprint. Prioritize above feature work."
            executive_action = f"Allocate security sprint resources. Add to risk register."
            timeline = "1-2 weeks"
            resources = ["Security Engineer", "Developer"]
            justification = f"High risk score {score:.2f}: {vuln_type} requires attention within 2 weeks."
        elif score >= 0.15:
            decision = Decision.MONITOR
            technical_action = f"Add monitoring and alerting for {vuln_type} patterns."
            executive_action = f"Add to security dashboard. Review quarterly."
            timeline = "Continuous monitoring"
            resources = ["DevOps", "Security Analyst"]
            justification = f"Medium risk score {score:.2f}: Monitor {vuln_type} for changes in threat landscape."
        else:
            decision = Decision.IGNORE
            technical_action = f"Accept residual risk for {vuln_type}. Document rationale."
            executive_action = f"Document in risk register. No immediate action required."
            timeline = "Review quarterly"
            resources = []
            justification = f"Low risk score {score:.2f}: {vuln_type} does not pose significant threat."

        return DecisionResult(
            decision=decision,
            priority_score=score,
            technical_action=technical_action,
            executive_action=executive_action,
            timeline=timeline,
            resources_needed=resources,
            justification=justification,
        )
