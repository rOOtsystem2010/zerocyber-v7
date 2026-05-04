"""ZeroCyber v7 — Software Composition Analysis (SCA) engine."""
import json
import os
import re
import subprocess
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path


@dataclass
class VulnerableDependency:
    package: str
    current_version: str
    fixed_version: str
    cve_id: str
    severity: str
    description: str
    ecosystem: str


class DependencyChecker:
    """Parse dependency files and check against known CVE database."""

    def __init__(self, cve_db_path: Optional[str] = None):
        if cve_db_path and os.path.exists(cve_db_path):
            with open(cve_db_path, 'r', encoding='utf-8') as f:
                self.cve_db = json.load(f)
        else:
            default_path = Path(__file__).parent.parent / 'known_cves.json'
            if default_path.exists():
                with open(default_path, 'r', encoding='utf-8') as f:
                    self.cve_db = json.load(f)
            else:
                self.cve_db = {"vulnerabilities": {}}

    def scan_project(self, project_path: str) -> List[VulnerableDependency]:
        """Scan all dependency files in project."""
        findings = []
        project_path = Path(project_path)

        # Python
        for dep_file in project_path.rglob('requirements.txt'):
            findings.extend(self._parse_requirements_txt(dep_file, 'python'))
        for dep_file in project_path.rglob('setup.py'):
            findings.extend(self._parse_setup_py(dep_file, 'python'))
        for dep_file in project_path.rglob('pyproject.toml'):
            findings.extend(self._parse_pyproject_toml(dep_file, 'python'))
        for dep_file in project_path.rglob('setup.cfg'):
            findings.extend(self._parse_setup_cfg(dep_file, 'python'))
        for dep_file in project_path.rglob('Pipfile'):
            findings.extend(self._parse_pipfile(dep_file, 'python'))
        for dep_file in project_path.rglob('poetry.lock'):
            findings.extend(self._parse_poetry_lock(dep_file, 'python'))

        # JavaScript/Node.js
        for dep_file in project_path.rglob('package.json'):
            findings.extend(self._parse_package_json(dep_file, 'javascript'))
        for dep_file in project_path.rglob('package-lock.json'):
            findings.extend(self._parse_package_lock(dep_file, 'javascript'))
        for dep_file in project_path.rglob('yarn.lock'):
            findings.extend(self._parse_yarn_lock(dep_file, 'javascript'))

        # Go
        for dep_file in project_path.rglob('go.mod'):
            findings.extend(self._parse_go_mod(dep_file, 'go'))
        for dep_file in project_path.rglob('go.sum'):
            findings.extend(self._parse_go_sum(dep_file, 'go'))

        return findings

    def _parse_requirements_txt(self, path: Path, ecosystem: str) -> List[VulnerableDependency]:
        """Parse requirements.txt format."""
        deps = []
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#') or line.startswith('-'):
                        continue
                    # Parse name==version or name>=version
                    match = re.match(r'^([a-zA-Z0-9_.-]+)([<>=!~]+[\d.]+[a-zA-Z0-9_.-]*)?', line)
                    if match:
                        name = match.group(1).lower()
                        version = match.group(2).lstrip('<>=!~') if match.group(2) else 'unknown'
                        deps.extend(self._check_cves(name, version, ecosystem, str(path)))
        except Exception:
            pass
        return deps

    def _parse_setup_py(self, path: Path, ecosystem: str) -> List[VulnerableDependency]:
        """Parse setup.py for install_requires."""
        deps = []
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            # Find install_requires list
            match = re.search(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL)
            if match:
                reqs = match.group(1)
                for req in re.findall(r'["\']([a-zA-Z0-9_.-]+[<>=!~]*[\d.]*)["\']', reqs):
                    parts = req.split('<>=!~')
                    name = parts[0].strip().lower()
                    version = parts[1].strip() if len(parts) > 1 else 'unknown'
                    deps.extend(self._check_cves(name, version, ecosystem, str(path)))
        except Exception:
            pass
        return deps

    def _parse_pyproject_toml(self, path: Path, ecosystem: str) -> List[VulnerableDependency]:
        """Parse pyproject.toml dependencies."""
        deps = []
        try:
            import tomllib
            with open(path, 'rb') as f:
                data = tomllib.load(f)

            # Poetry dependencies
            poetry = data.get('tool', {}).get('poetry', {})
            for section in ['dependencies', 'dev-dependencies', 'group']:
                if section in poetry:
                    if isinstance(poetry[section], dict):
                        for name, ver in poetry[section].items():
                            if name == 'python':
                                continue
                            version = str(ver).lstrip('^~>=<') if ver != '*' else 'unknown'
                            deps.extend(self._check_cves(name.lower(), version, ecosystem, str(path)))

            # PEP 621
            project = data.get('project', {})
            for req in project.get('dependencies', []):
                match = re.match(r'^([a-zA-Z0-9_.-]+)([<>=!~]+[\d.]*)?', req)
                if match:
                    name = match.group(1).lower()
                    version = match.group(2).lstrip('<>=!~') if match.group(2) else 'unknown'
                    deps.extend(self._check_cves(name, version, ecosystem, str(path)))

        except ImportError:
            # Fallback for Python < 3.11
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                # Simple regex parsing for TOML
                for line in content.split('\n'):
                    line = line.strip()
                    if '=' in line and not line.startswith('[') and not line.startswith('#'):
                        parts = line.split('=')
                        if len(parts) >= 2:
                            name = parts[0].strip().strip('"\'').lower()
                            version = parts[1].strip().strip('"\'').strip('^~>=<!').strip('*')
                            if name and version and name not in ('python', 'name', 'version', 'description'):
                                deps.extend(self._check_cves(name, version, ecosystem, str(path)))
            except Exception:
                pass
        except Exception:
            pass
        return deps

    def _parse_setup_cfg(self, path: Path, ecosystem: str) -> List[VulnerableDependency]:
        """Parse setup.cfg for install_requires."""
        deps = []
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                in_requires = False
                for line in f:
                    line = line.strip()
                    if line.startswith('install_requires'):
                        in_requires = True
                        continue
                    if in_requires:
                        if not line or line.startswith('['):
                            break
                        # Handle multi-line with indentation
                        if line.startswith('install_requires') or (line and not line.startswith('#')):
                            match = re.match(r'^([a-zA-Z0-9_.-]+)([<>=!~]+[\d.]*)?', line)
                            if match:
                                name = match.group(1).lower()
                                version = match.group(2).lstrip('<>=!~') if match.group(2) else 'unknown'
                                deps.extend(self._check_cves(name, version, ecosystem, str(path)))
        except Exception:
            pass
        return deps

    def _parse_pipfile(self, path: Path, ecosystem: str) -> List[VulnerableDependency]:
        """Parse Pipfile for dependencies."""
        deps = []
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                in_packages = False
                for line in f:
                    line = line.strip()
                    if line == '[packages]' or line == '[dev-packages]':
                        in_packages = True
                        continue
                    if line.startswith('[') and in_packages:
                        in_packages = False
                        continue
                    if in_packages and '=' in line:
                        parts = line.split('=')
                        name = parts[0].strip().strip('"\'').lower()
                        version = parts[1].strip().strip('"\'').strip('^~>=<!*') if len(parts) > 1 else 'unknown'
                        deps.extend(self._check_cves(name, version, ecosystem, str(path)))
        except Exception:
            pass
        return deps

    def _parse_poetry_lock(self, path: Path, ecosystem: str) -> List[VulnerableDependency]:
        """Parse poetry.lock for exact versions."""
        deps = []
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                current_name = None
                for line in f:
                    line = line.strip()
                    if line.startswith('name = '):
                        current_name = line.split('=')[1].strip().strip('"\'').lower()
                    elif line.startswith('version = ') and current_name:
                        version = line.split('=')[1].strip().strip('"\'')
                        deps.extend(self._check_cves(current_name, version, ecosystem, str(path)))
                        current_name = None
        except Exception:
            pass
        return deps

    def _parse_package_json(self, path: Path, ecosystem: str) -> List[VulnerableDependency]:
        """Parse package.json dependencies."""
        deps = []
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            for section in ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']:
                for name, version in data.get(section, {}).items():
                    clean_ver = version.lstrip('^~>=<!*')
                    deps.extend(self._check_cves(name.lower(), clean_ver, ecosystem, str(path)))
        except Exception:
            pass
        return deps

    def _parse_package_lock(self, path: Path, ecosystem: str) -> List[VulnerableDependency]:
        """Parse package-lock.json v2+ and v1."""
        deps = []
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            # v2+ format
            packages = data.get('packages', {})
            for name, info in packages.items():
                if name.startswith('node_modules/'):
                    pkg_name = name.replace('node_modules/', '')
                    version = info.get('version', 'unknown')
                    deps.extend(self._check_cves(pkg_name.lower(), version, ecosystem, str(path)))
            # v1 format fallback
            deps_v1 = data.get('dependencies', {})
            for name, info in deps_v1.items():
                version = info.get('version', 'unknown')
                deps.extend(self._check_cves(name.lower(), version, ecosystem, str(path)))
        except Exception:
            pass
        return deps

    def _parse_yarn_lock(self, path: Path, ecosystem: str) -> List[VulnerableDependency]:
        """Parse yarn.lock for dependencies."""
        deps = []
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                current_name = None
                for line in f:
                    line = line.strip()
                    if line.startswith('@') or (not line.startswith('#') and not line.startswith(' ') and '@' in line):
                        # Package line: "package@version" or "@scope/package@version"
                        match = re.match(r'^(@?[^@]+)@[^\d]*([\d.]+)', line)
                        if match:
                            current_name = match.group(1).strip().strip('"\'').lower()
                    elif line.startswith('version ') and current_name:
                        version = line.split(' ')[1].strip().strip('"\'')
                        deps.extend(self._check_cves(current_name, version, ecosystem, str(path)))
                        current_name = None
        except Exception:
            pass
        return deps

    def _parse_go_mod(self, path: Path, ecosystem: str) -> List[VulnerableDependency]:
        """Parse go.mod for dependencies."""
        deps = []
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                in_require = False
                for line in f:
                    line = line.strip()
                    if line == 'require (':
                        in_require = True
                        continue
                    if in_require and line == ')':
                        in_require = False
                        continue
                    if in_require or line.startswith('require '):
                        # Format: module vX.Y.Z or module vX.Y.Z // indirect
                        match = re.match(r'^([^\s]+)\s+(v[\d.]+[^\s]*)', line)
                        if match:
                            name = match.group(1).strip().lower()
                            version = match.group(2).strip()
                            deps.extend(self._check_cves(name, version, ecosystem, str(path)))
        except Exception:
            pass
        return deps

    def _parse_go_sum(self, path: Path, ecosystem: str) -> List[VulnerableDependency]:
        """Parse go.sum for dependencies."""
        deps = []
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                seen = set()
                for line in f:
                    line = line.strip()
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[0].strip().lower()
                        version = parts[1].strip()
                        if name not in seen:
                            seen.add(name)
                            deps.extend(self._check_cves(name, version, ecosystem, str(path)))
        except Exception:
            pass
        return deps

    def _check_cves(self, name: str, version: str, ecosystem: str, source_file: str) -> List[VulnerableDependency]:
        """Check a dependency against the CVE database."""
        findings = []
        vulns = self.cve_db.get('vulnerabilities', {}).get(ecosystem, {})
        pkg_vulns = vulns.get(name, [])

        for vuln in pkg_vulns:
            affected = vuln.get('affected', '')
            if self._version_affected(version, affected):
                findings.append(VulnerableDependency(
                    package=name,
                    current_version=version,
                    fixed_version=vuln.get('fixed', 'unknown'),
                    cve_id=vuln.get('cve_id', 'N/A'),
                    severity=vuln.get('severity', 'UNKNOWN'),
                    description=vuln.get('description', 'No description'),
                    ecosystem=ecosystem,
                ))
        return findings

    def _version_affected(self, current: str, affected_spec: str) -> bool:
        """Check if current version is affected by the spec."""
        if not current or current == 'unknown':
            return False
        current = current.strip().lstrip('v')
        specs = affected_spec.split(',')
        for spec in specs:
            spec = spec.strip()
            if spec.startswith('<'):
                max_ver = spec.lstrip('<=').strip()
                if self._compare_versions(current, max_ver) < 0:
                    return True
            elif spec.startswith('>='):
                min_ver = spec.lstrip('>=').strip()
                if self._compare_versions(current, min_ver) >= 0:
                    return True
            elif spec.startswith('>'):
                min_ver = spec.lstrip('>').strip()
                if self._compare_versions(current, min_ver) > 0:
                    return True
            elif spec.startswith('<='):
                max_ver = spec.lstrip('<=').strip()
                if self._compare_versions(current, max_ver) <= 0:
                    return True
        return False

    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare two semantic versions. Returns -1, 0, or 1."""
        try:
            def normalize(v):
                parts = re.split(r'[.-]', v)
                result = []
                for p in parts:
                    if p.isdigit():
                        result.append(int(p))
                    else:
                        result.append(p)
                return result

            n1 = normalize(v1)
            n2 = normalize(v2)
            for a, b in zip(n1, n2):
                if isinstance(a, int) and isinstance(b, int):
                    if a < b:
                        return -1
                    elif a > b:
                        return 1
                elif str(a) < str(b):
                    return -1
                elif str(a) > str(b):
                    return 1
            if len(n1) < len(n2):
                return -1
            elif len(n1) > len(n2):
                return 1
            return 0
        except Exception:
            return 0 if v1 == v2 else (-1 if v1 < v2 else 1)
