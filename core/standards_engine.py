"""ZeroCyber v7 — Standards compliance engine (CWE, CVSS, OWASP, CAPEC, NIST, PCI DSS)."""
import json
import os
from typing import Dict, Any, Optional, List
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class ComplianceMapping:
    cwe_id: str
    cwe_description: str
    cvss_base_vector: str
    cvss_base_score: float
    owasp_2026: str
    capec_id: str
    nist_800_53: List[str] = field(default_factory=list)
    pci_dss: List[str] = field(default_factory=list)


class StandardsEngine:
    """Map vulnerability types to security standards."""

    def __init__(self, standards_path: Optional[str] = None):
        if standards_path and os.path.exists(standards_path):
            with open(standards_path, 'r', encoding='utf-8') as f:
                self.standards = json.load(f)
        else:
            default_path = Path(__file__).parent.parent / 'standards.json'
            if default_path.exists():
                with open(default_path, 'r', encoding='utf-8') as f:
                    self.standards = json.load(f)
            else:
                self.standards = {"mappings": {}}

    def get_mapping(self, vuln_type: str) -> ComplianceMapping:
        """Get standards mapping for a vulnerability type."""
        mapping = self.standards.get('mappings', {}).get(vuln_type, {})
        if not mapping:
            # Default fallback
            mapping = {
                "cwe": "CWE-UNKNOWN",
                "cwe_description": "Unknown vulnerability type",
                "cvss_base_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                "cvss_base_score": 0.0,
                "owasp_2026": "Unknown",
                "capec": "CAPEC-UNKNOWN",
                "nist_800_53": [],
                "pci_dss": [],
            }
        return ComplianceMapping(
            cwe_id=mapping.get('cwe', 'CWE-UNKNOWN'),
            cwe_description=mapping.get('cwe_description', 'No description'),
            cvss_base_vector=mapping.get('cvss_base_vector', ''),
            cvss_base_score=mapping.get('cvss_base_score', 0.0),
            owasp_2026=mapping.get('owasp_2026', 'Unknown'),
            capec_id=mapping.get('capec', 'CAPEC-UNKNOWN'),
            nist_800_53=mapping.get('nist_800_53', []),
            pci_dss=mapping.get('pci_dss', []),
        )

    def compute_dynamic_cvss(self, base_mapping: ComplianceMapping,
                             has_sanitization: bool = False,
                             requires_auth: bool = False,
                             is_test_file: bool = False,
                             interprocedural: bool = True,
                             source_type: str = 'EXTERNAL') -> Dict[str, Any]:
        """Compute dynamic CVSS v3.1 score based on actual code context."""
        adjustments = self.standards.get('cvss_adjustments', {})
        base_score = base_mapping.cvss_base_score

        # Parse base vector
        vector = base_mapping.cvss_base_vector
        av = self._extract_metric(vector, 'AV')
        ac = self._extract_metric(vector, 'AC')
        pr = self._extract_metric(vector, 'PR')
        ui = self._extract_metric(vector, 'UI')
        s = self._extract_metric(vector, 'S')
        c = self._extract_metric(vector, 'C')
        i = self._extract_metric(vector, 'I')
        a = self._extract_metric(vector, 'A')

        # Adjust based on actual context
        score = base_score

        # Sanitization reduces impact
        if has_sanitization:
            score = max(0.0, score - 2.0)

        # Auth required reduces likelihood
        if requires_auth:
            score = max(0.0, score - 1.5)
            if pr in ('N', 'L'):
                pr = 'H'  # Privileges Required becomes High

        # Test files are lower priority
        if is_test_file:
            score = max(0.0, score - 3.0)

        # Inter-procedural flow increases impact
        if interprocedural:
            score = min(10.0, score + 0.5)

        # External source is worse
        if source_type == 'EXTERNAL':
            score = min(10.0, score + 0.3)

        # Recalculate severity
        severity = self._score_to_severity(score)

        # Rebuild vector
        new_vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

        return {
            'base_score': base_score,
            'temporal_score': round(score, 1),
            'severity': severity,
            'vector': new_vector,
            'metrics': {
                'attack_vector': av,
                'attack_complexity': ac,
                'privileges_required': pr,
                'user_interaction': ui,
                'scope': s,
                'confidentiality': c,
                'integrity': i,
                'availability': a,
            },
            'adjustments': {
                'has_sanitization': has_sanitization,
                'requires_auth': requires_auth,
                'is_test_file': is_test_file,
                'interprocedural': interprocedural,
                'source_type': source_type,
            }
        }

    def _extract_metric(self, vector: str, metric: str) -> str:
        """Extract a metric value from CVSS vector."""
        import re
        match = re.search(rf'/{metric}:([A-Z])', vector)
        return match.group(1) if match else 'N'

    def _score_to_severity(self, score: float) -> str:
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        elif score > 0.0:
            return 'LOW'
        return 'INFO'

    def get_confidence_rules(self) -> Dict[str, Dict[str, Any]]:
        """Get confidence scoring rules."""
        return self.standards.get('confidence_rules', {
            'LOW': {'description': 'Pattern match only', 'min_score': 0.0, 'max_score': 0.3},
            'MEDIUM': {'description': 'Local flow within function', 'min_score': 0.3, 'max_score': 0.6},
            'HIGH': {'description': 'Inter-procedural flow with no sanitization', 'min_score': 0.6, 'max_score': 1.0},
        })
