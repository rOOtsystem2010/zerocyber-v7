"""ZeroCyber v7 — Command Line Interface"""
import argparse
import json
import sys
import os
import time
import uuid
import tempfile
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

from core.parser import scan_project
from core.taint_engine import TaintEngine
from core.dependency_checker import DependencyChecker
from core.standards_engine import StandardsEngine, ComplianceMapping
from core.business_engine import BusinessEngine, AssetClassification, Decision, BusinessImpact, DecisionResult
from core.reporter import ScanResult, JSONReporter, SARIFReporter, HTMLReporter


# ── Version ──
VERSION = "7.0.0"


def create_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zerocyber",
        description="ZeroCyber v7.0 — Multi-language AI Security Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  zerocyber scan /path/to/project --format sarif --output report.sarif
  zerocyber scan https://github.com/owner/repo --format html --include-all
  zerocyber scan ./my-app --format json --show-low --explain-fp
  zerocyber check-deps ./project --update-cve-db
        """
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a project for vulnerabilities")
    scan_parser.add_argument("target", help="Path to local project or GitHub URL")
    scan_parser.add_argument("-f", "--format", choices=["json", "sarif", "html", "all"], default="json",
                             help="Output format (default: json)")
    scan_parser.add_argument("-o", "--output", help="Output file path (default: stdout)")
    scan_parser.add_argument("--include-all", action="store_true",
                             help="Include test files, examples, and docs")
    scan_parser.add_argument("--show-low", action="store_true",
                             help="Include LOW confidence findings")
    scan_parser.add_argument("--explain-fp", action="store_true",
                             help="Show false positive explanations")
    scan_parser.add_argument("--no-deps", action="store_true",
                             help="Skip dependency vulnerability scanning")
    scan_parser.add_argument("--depth", type=int, default=5,
                             help="Max call graph depth for cross-file analysis")
    scan_parser.add_argument("-v", "--verbose", action="store_true",
                             help="Verbose output")
    scan_parser.add_argument("--workers", type=int, default=8,
                             help="Number of parallel workers (default: 8)")
    scan_parser.add_argument("--no-standards", action="store_true",
                             help="Skip standards compliance mapping (faster)")
    scan_parser.add_argument("--no-business", action="store_true",
                             help="Skip business impact analysis (faster)")

    # check-deps command
    deps_parser = subparsers.add_parser("check-deps", help="Check dependencies for known vulnerabilities")
    deps_parser.add_argument("target", help="Path to project")
    deps_parser.add_argument("-o", "--output", help="Output file path")
    deps_parser.add_argument("--update-cve-db", action="store_true",
                              help="Update CVE database from remote")
    deps_parser.add_argument("-f", "--format", choices=["json", "sarif", "html"], default="json")

    return parser


def clone_github_repo(repo_url: str, verbose: bool = False) -> str:
    """Clone a GitHub repository to a temporary directory."""
    temp_dir = tempfile.mkdtemp(prefix="zerocyber_v7_")
    if verbose:
        print(f"[+] Cloning {repo_url} -> {temp_dir}")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, temp_dir],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            print(f"[!] Git clone failed: {result.stderr}", file=sys.stderr)
            shutil.rmtree(temp_dir, ignore_errors=True)
            sys.exit(1)
        return temp_dir
    except subprocess.TimeoutExpired:
        print("[!] Git clone timed out", file=sys.stderr)
        shutil.rmtree(temp_dir, ignore_errors=True)
        sys.exit(1)
    except FileNotFoundError:
        print("[!] git command not found. Please install Git.", file=sys.stderr)
        sys.exit(1)


def scan_project_v7(target_path: str, args) -> ScanResult:
    """Run full ZeroCyber v7 scan pipeline."""
    start_time = time.time()

    if args.verbose:
        print(f"[+] ZeroCyber v{VERSION} starting scan...")
        print(f"[+] Target: {target_path}")

    # Phase 1: Parse project
    if args.verbose:
        print("[+] Phase 1: Parsing source files...")
    parsed_files, call_graph, total_files, parsed_count = scan_project(
        target_path,
        include_all=args.include_all,
        max_workers=args.workers
    )
    coverage = (parsed_count / total_files * 100) if total_files > 0 else 0.0

    if args.verbose:
        print(f"    Scanned {parsed_count}/{total_files} files ({coverage:.1f}% coverage)")
        languages = {}
        for pf in parsed_files:
            languages[pf.language] = languages.get(pf.language, 0) + 1
        for lang, count in languages.items():
            print(f"    {lang}: {count} files")

    # Phase 2: Taint analysis
    if args.verbose:
        print("[+] Phase 2: Running taint analysis...")
    taint_engine = TaintEngine()
    taint_flows = taint_engine.analyze_project(target_path, parsed_files, include_all=args.include_all)

    if args.verbose:
        print(f"    Found {len(taint_flows)} potential taint flows")

    # Phase 3: Dependency scanning
    dep_vulns = []
    if not args.no_deps:
        if args.verbose:
            print("[+] Phase 3: Scanning dependencies...")
        dep_checker = DependencyChecker()
        dep_vulns_raw = dep_checker.scan_project(target_path)
        for dv in dep_vulns_raw:
            dep_vulns.append({
                'package': dv.package,
                'current_version': dv.current_version,
                'fixed_version': dv.fixed_version,
                'cve_id': dv.cve_id,
                'severity': dv.severity,
                'description': dv.description,
                'ecosystem': dv.ecosystem,
            })
        if args.verbose:
            print(f"    Found {len(dep_vulns)} vulnerable dependencies")

    # Phase 4: Standards mapping + business impact
    standards_engine = None if args.no_standards else StandardsEngine()
    business_engine = None if args.no_business else BusinessEngine()

    vulnerabilities = []
    standards = standards_engine or StandardsEngine()
    business = business_engine or BusinessEngine()

    # Asset discovery
    assets = []
    for pf in parsed_files:
        try:
            text = Path(pf.path).read_text(encoding='utf-8', errors='ignore').lower()
            if any(x in text for x in ['payment', 'stripe', 'billing', 'charge', 'card', 'pay']):
                assets.append(AssetClassification(name=f"Payment in {Path(pf.path).name}", asset_type='payment', value=10.0, exposure='public'))
            if any(x in text for x in ['auth', 'login', 'jwt', 'session', 'password', 'oauth']):
                assets.append(AssetClassification(name=f"Auth in {Path(pf.path).name}", asset_type='authentication', value=9.0, exposure='public'))
            if any(x in text for x in ['email', 'phone', 'pii', 'ssn', 'personal', 'gdpr']):
                assets.append(AssetClassification(name=f"PII in {Path(pf.path).name}", asset_type='pii', value=8.5, exposure='public'))
            if 'api_key' in text or 'secret_key' in text or 'private_key' in text:
                assets.append(AssetClassification(name=f"Secrets in {Path(pf.path).name}", asset_type='api_key', value=7.0, exposure='internal'))
        except Exception:
            pass

    for flow in taint_flows:
        # Confidence filter
        if flow.confidence == 'LOW' and not args.show_low:
            continue

        # Standards mapping
        mapping = standards.get_mapping(flow.sink.sink_type)

        # Dynamic CVSS
        cvss = standards.compute_dynamic_cvss(
            mapping,
            has_sanitization=len(flow.sanitizers) > 0,
            requires_auth=False,
            is_test_file='test' in flow.sink.file.lower(),
            interprocedural=len(flow.path) > 1,
            source_type=flow.source.source_type,
        )

        # Business impact
        biz_impact = business.analyze(
            flow.sink.sink_type,
            flow.source.source_type,
            flow.confidence,
            flow.risk_score,
            has_sanitization=len(flow.sanitizers) > 0,
            assets=assets,
        )

        # Decision
        decision = business.make_decision(
            flow.sink.sink_type,
            flow.confidence,
            flow.risk_score,
            has_sanitization=len(flow.sanitizers) > 0,
            is_test_file='test' in flow.sink.file.lower(),
            source_type=flow.source.source_type,
            cvss_score=cvss['temporal_score'],
            business_impact=biz_impact,
        )

        # Code snippet
        snippet = ""
        try:
            lines = Path(flow.sink.file).read_text(encoding='utf-8', errors='ignore').splitlines()
            start = max(0, flow.sink.line - 3)
            end = min(len(lines), flow.sink.line + 2)
            snippet = '\n'.join(lines[start:end])
        except Exception:
            pass

        vuln = {
            'vuln_id': f"ZCV7-{uuid.uuid4().hex[:8].upper()}",
            'vuln_type': flow.sink.sink_type,
            'title': f"{flow.sink.sink_type} in {Path(flow.sink.file).name}",
            'description': f"{flow.sink.sink_type} vulnerability: tainted data from {flow.source.name} reaches {flow.sink.name}",
            'file_path': flow.sink.file,
            'line_number': flow.sink.line,
            'function_name': flow.sink.name,
            'severity': _severity_from_score(cvss['temporal_score']),
            'confidence': flow.confidence,
            'cvss_score': cvss['temporal_score'],
            'cvss_vector': cvss['vector'],
            'cvss_metrics': cvss['metrics'],
            'cwe_id': mapping.cwe_id,
            'cwe_description': mapping.cwe_description,
            'owasp_category': mapping.owasp_2026,
            'capec_id': mapping.capec_id,
            'nist_800_53': mapping.nist_800_53,
            'pci_dss': mapping.pci_dss,
            'source': {
                'name': flow.source.name,
                'line': flow.source.line,
                'file': flow.source.file,
                'source_type': flow.source.source_type,
            },
            'sink': {
                'name': flow.sink.name,
                'line': flow.sink.line,
                'file': flow.sink.file,
                'sink_type': flow.sink.sink_type,
                'arguments': flow.sink.arguments,
            },
            'taint_path': flow.path,
            'sanitizers': flow.sanitizers,
            'risk_score': flow.risk_score,
            'code_snippet': snippet,
            'attack_chain': self._build_attack_chain(flow),
            'business_impact': {
                'financial_loss_estimate': biz_impact.financial_loss_estimate,
                'users_affected_estimate': biz_impact.users_affected_estimate,
                'systems_affected': biz_impact.systems_affected,
                'reputation_risk': biz_impact.reputation_risk,
                'compliance_risk': biz_impact.compliance_risk,
                'operational_downtime': biz_impact.operational_downtime,
                'data_breach_risk': biz_impact.data_breach_risk,
            },
            'decision': {
                'decision': decision.decision.value,
                'priority_score': round(decision.priority_score, 3),
                'technical_action': decision.technical_action,
                'executive_action': decision.executive_action,
                'timeline': decision.timeline,
                'resources_needed': decision.resources_needed,
                'justification': decision.justification,
            },
            'remediation': {
                'technical_fix': f"Sanitize input before passing to {flow.sink.name}. Use parameterized queries or safe APIs.",
                'executive_action': decision.executive_action,
                'mitigation_steps': [
                    f"1. Replace {flow.sink.name} with safe alternative",
                    f"2. Add input validation and sanitization",
                    f"3. Implement parameterized interfaces",
                    f"4. Run regression tests",
                ],
                'verification_steps': [
                    f"Test with malicious payloads targeting {flow.sink.sink_type}",
                    f"Verify sanitization blocks attack vectors",
                    f"Review all call sites of {flow.sink.name}",
                ],
            },
        }
        vulnerabilities.append(vuln)

    # Deduplicate by file+line+sink_type
    seen = set()
    unique_vulns = []
    for v in vulnerabilities:
        key = (v['file_path'], v['line_number'], v['vuln_type'])
        if key not in seen:
            seen.add(key)
            unique_vulns.append(v)

    # Sort by CVSS score descending
    unique_vulns.sort(key=lambda x: x['cvss_score'], reverse=True)

    scan_duration = time.time() - start_time

    # Statistics
    severity_breakdown = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    decision_breakdown = {'FIX_NOW': 0, 'FIX_SOON': 0, 'MONITOR': 0, 'IGNORE': 0}
    for v in unique_vulns:
        severity_breakdown[v['severity']] = severity_breakdown.get(v['severity'], 0) + 1
        decision_breakdown[v['decision']['decision']] = decision_breakdown.get(v['decision']['decision'], 0) + 1

    # Executive summary
    exec_summary = f"ZeroCyber v{VERSION} analyzed {parsed_count} files ({coverage:.1f}% coverage). "
    if unique_vulns:
        crit = severity_breakdown['CRITICAL']
        high = severity_breakdown['HIGH']
        exec_summary += f"Found {len(unique_vulns)} vulnerabilities ({crit} Critical, {high} High). "
        exec_summary += f"{decision_breakdown['FIX_NOW']} require immediate action. "
    else:
        exec_summary += "No vulnerabilities detected. "
    if dep_vulns:
        exec_summary += f"{len(dep_vulns)} vulnerable dependencies identified."

    languages = {}
    for pf in parsed_files:
        languages[pf.language] = languages.get(pf.language, 0) + 1

    return ScanResult(
        metadata={
            'tool': 'ZeroCyber',
            'version': VERSION,
            'generated_at': datetime.now().isoformat(),
            'start_time': datetime.fromtimestamp(start_time).isoformat(),
            'project_path': target_path,
        },
        system_summary=exec_summary,
        files_scanned=parsed_count,
        total_files=total_files,
        coverage_percent=coverage,
        total_loc=sum(pf.loc for pf in parsed_files),
        languages=languages,
        scan_duration=scan_duration,
        vulnerabilities=unique_vulns,
        dependency_vulns=dep_vulns,
        statistics={
            'severity_breakdown': severity_breakdown,
            'decision_breakdown': decision_breakdown,
            'total_taint_flows': len(taint_flows),
            'assets_found': len(assets),
            'languages': languages,
        },
        executive_summary=exec_summary,
    )


def _build_attack_chain(flow):
    """Build attack chain steps for a taint flow."""
    steps = []
    steps.append({
        'technique': 'recon',
        'description': f"Identify {flow.source.source_type.lower()} input source: {flow.source.name}",
        'confidence': 0.9,
        'prerequisites': ['Application access'],
    })
    steps.append({
        'technique': 'weaponize',
        'description': f"Craft payload targeting {flow.sink.sink_type}",
        'confidence': 0.85,
        'prerequisites': [f"Knowledge of {flow.sink.sink_type} vectors"],
    })
    steps.append({
        'technique': 'exploit',
        'description': f"Submit payload to reach {flow.sink.name}",
        'confidence': flow.risk_score,
        'prerequisites': ['Valid input channel'],
    })
    steps.append({
        'technique': 'escalate',
        'description': f"Achieve {flow.sink.sink_type} impact",
        'confidence': flow.risk_score * 0.9,
        'prerequisites': ['Successful payload delivery'],
    })
    return steps


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


def main():
    parser = create_argument_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "scan":
        target = args.target
        temp_dir = None

        # Check if target is GitHub URL
        if target.startswith("http://") or target.startswith("https://") or target.startswith("git@"):
            temp_dir = clone_github_repo(target, verbose=args.verbose)
            target = temp_dir

        if not os.path.exists(target):
            print(f"[!] Target not found: {target}", file=sys.stderr)
            sys.exit(1)

        result = scan_project_v7(target, args)

        # Generate output
        if args.format == "json" or args.format == "all":
            reporter = JSONReporter()
            output = reporter.generate(result)
            if args.output and args.format != "all":
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(output)
                print(f"[+] JSON report saved to: {args.output}")
            elif args.format == "all":
                base = args.output or "zerocyber_report"
                with open(f"{base}.json", 'w', encoding='utf-8') as f:
                    f.write(output)
                print(f"[+] JSON report saved to: {base}.json")
            else:
                print(output)

        if args.format == "sarif" or args.format == "all":
            reporter = SARIFReporter()
            output = reporter.generate(result)
            if args.output and args.format != "all":
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(output)
                print(f"[+] SARIF report saved to: {args.output}")
            elif args.format == "all":
                base = args.output or "zerocyber_report"
                with open(f"{base}.sarif", 'w', encoding='utf-8') as f:
                    f.write(output)
                print(f"[+] SARIF report saved to: {base}.sarif")
            else:
                print(output)

        if args.format == "html" or args.format == "all":
            reporter = HTMLReporter()
            output = reporter.generate(result)
            if args.output and args.format != "all":
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(output)
                print(f"[+] HTML report saved to: {args.output}")
            elif args.format == "all":
                base = args.output or "zerocyber_report"
                with open(f"{base}.html", 'w', encoding='utf-8') as f:
                    f.write(output)
                print(f"[+] HTML report saved to: {base}.html")
            else:
                print(output)

        # Print summary
        print("\n" + "=" * 60)
        print(f"ZeroCyber v{VERSION} Scan Summary")
        print("=" * 60)
        print(f"Files Scanned: {result.files_scanned} / {result.total_files} ({result.coverage_percent:.1f}%)")
        print(f"Total LOC: {result.total_loc:,}")
        print(f"Vulnerabilities: {len(result.vulnerabilities)}")
        print(f"Dependency Vulns: {len(result.dependency_vulns)}")
        stats = result.statistics
        sev = stats.get('severity_breakdown', {})
        print(f"  CRITICAL: {sev.get('CRITICAL', 0)} | HIGH: {sev.get('HIGH', 0)} | MEDIUM: {sev.get('MEDIUM', 0)} | LOW: {sev.get('LOW', 0)}")
        dec = stats.get('decision_breakdown', {})
        print(f"  FIX_NOW: {dec.get('FIX_NOW', 0)} | FIX_SOON: {dec.get('FIX_SOON', 0)} | MONITOR: {dec.get('MONITOR', 0)} | IGNORE: {dec.get('IGNORE', 0)}")
        print(f"Scan Duration: {result.scan_duration:.2f}s")
        print("=" * 60)

        # Cleanup temp dir if cloned
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)

    elif args.command == "check-deps":
        if not os.path.exists(args.target):
            print(f"[!] Target not found: {args.target}", file=sys.stderr)
            sys.exit(1)

        checker = DependencyChecker()
        vulns = checker.scan_project(args.target)

        results = []
        for v in vulns:
            results.append({
                'package': v.package,
                'current_version': v.current_version,
                'fixed_version': v.fixed_version,
                'cve_id': v.cve_id,
                'severity': v.severity,
                'description': v.description,
                'ecosystem': v.ecosystem,
            })

        if args.format == "json":
            output = json.dumps(results, indent=2)
        elif args.format == "sarif":
            # Simple SARIF for deps
            sarif = {
                "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                "version": "2.1.0",
                "runs": [{
                    "tool": {"driver": {"name": "ZeroCyber", "version": VERSION}},
                    "results": [
                        {
                            "ruleId": v['cve_id'],
                            "level": "error" if v['severity'] in ['CRITICAL', 'HIGH'] else "warning",
                            "message": {"text": f"{v['package']}@{v['current_version']}: {v['description']}"},
                            "properties": v,
                        }
                        for v in results
                    ]
                }]
            }
            output = json.dumps(sarif, indent=2)
        else:
            output = json.dumps(results, indent=2)

        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"[+] Report saved to: {args.output}")
        else:
            print(output)

        print(f"\n[+] Found {len(results)} vulnerable dependencies")


if __name__ == "__main__":
    main()
