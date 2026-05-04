"""ZeroCyber v7 — Advanced cross-file taint analysis engine."""
import re
import os
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from pathlib import Path

from tree_sitter import Parser, Node

import tree_sitter_python as tspython
import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts
import tree_sitter_go as tsgo


def _get_ts_language(lang_name: str = 'typescript'):
    return tsts.language_typescript() if lang_name == 'typescript' else tsts.language_tsx()



@dataclass
class TaintSource:
    name: str
    line: int
    file: str
    source_type: str  # 'EXTERNAL', 'ENVIRONMENT', 'FILE'
    confidence: float = 1.0


@dataclass
class TaintSink:
    name: str
    line: int
    file: str
    sink_type: str
    arguments: List[str] = field(default_factory=list)


@dataclass
class TaintFlow:
    source: TaintSource
    sink: TaintSink
    path: List[str] = field(default_factory=list)
    sanitizers: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    confidence: str = "LOW"  # LOW, MEDIUM, HIGH


class TaintEngine:
    """Multi-language taint analysis with inter-procedural tracking."""

    # Language-specific external sources
    SOURCES = {
        'python': {
            'request.args.get', 'request.form.get', 'request.json',
            'request.get_json', 'request.headers.get', 'request.cookies.get',
            'request.files', 'request.values', 'request.data',
            'input(', 'sys.argv', 'os.environ.get', 'os.getenv',
            'open(', '__import__',
        },
        'javascript': {
            'req.query', 'req.body', 'req.params', 'req.headers',
            'req.cookies', 'req.files', 'request.query', 'request.body',
            'process.argv', 'process.env', 'window.location.search',
            'document.URL', 'document.location.href', 'localStorage.getItem',
            'URLSearchParams', 'fetch(', 'XMLHttpRequest',
        },
        'typescript': {
            'req.query', 'req.body', 'req.params', 'req.headers',
            'process.argv', 'process.env', 'window.location.search',
        },
        'go': {
            'r.URL.Query()', 'r.FormValue', 'r.PostFormValue',
            'r.Header.Get', 'r.Body', 'os.Args', 'os.Getenv',
            'bufio.NewReader', 'ioutil.ReadFile',
        },
    }

    # Language-specific dangerous sinks
    SINKS = {
        'python': {
            'Command Injection': ['os.system', 'os.popen', 'subprocess.call', 'subprocess.run',
                                  'subprocess.Popen', 'subprocess.check_output', 'subprocess.check_call',
                                  'exec', 'eval', 'compile'],
            'Code Injection': ['exec', 'eval', 'compile', '__import__'],
            'SQL Injection': ['cursor.execute', 'cursor.executemany', 'cursor.executescript',
                              'db.execute', 'db.query', 'session.execute', 'raw_query'],
            'SSRF': ['requests.get', 'requests.post', 'requests.put', 'requests.delete',
                     'urllib.request.urlopen', 'urllib.urlopen', 'http.client.HTTPConnection'],
            'Path Traversal': ['open', 'os.path.join', 'shutil.copy', 'shutil.move'],
            'Insecure Deserialization': ['pickle.loads', 'pickle.load', 'yaml.load',
                                          'json.loads', 'marshal.loads', 'dill.loads'],
            'XSS': ['render_template_string', 'Markup', 'mark_safe', 'innerHTML', 'document.write'],
            'Hardcoded Secret': ['api_key', 'secret_key', 'password', 'token', 'private_key'],
        },
        'javascript': {
            'Command Injection': ['exec', 'execSync', 'spawn', 'child_process.exec',
                                  'child_process.execSync', 'child_process.spawn'],
            'Code Injection': ['eval', 'Function', 'setTimeout', 'setInterval'],
            'SQL Injection': ['query', 'execute', 'run', 'all', 'get', 'prepare',
                              'sequelize.query', 'knex.raw'],
            'SSRF': ['fetch', 'axios.get', 'axios.post', 'request', 'http.get', 'https.get'],
            'Path Traversal': ['fs.readFile', 'fs.readFileSync', 'fs.writeFile', 'fs.writeFileSync',
                               'fs.createReadStream', 'fs.createWriteStream', 'fs.openSync'],
            'Insecure Deserialization': ['JSON.parse', 'eval', 'vm.runInContext', 'vm.runInNewContext'],
            'XSS': ['innerHTML', 'outerHTML', 'document.write', 'document.writeln', 'eval'],
            'Prototype Pollution': ['_.merge', 'lodash.merge', 'Object.assign', 'extend'],
        },
        'typescript': {
            'Command Injection': ['exec', 'execSync', 'spawn', 'child_process.exec',
                                  'child_process.execSync', 'child_process.spawn'],
            'Code Injection': ['eval', 'Function', 'setTimeout', 'setInterval'],
            'SQL Injection': ['query', 'execute', 'run', 'all', 'get', 'prepare'],
            'SSRF': ['fetch', 'axios.get', 'axios.post', 'request', 'http.get'],
            'Path Traversal': ['fs.readFile', 'fs.readFileSync', 'fs.writeFile', 'fs.writeFileSync'],
            'Insecure Deserialization': ['JSON.parse', 'eval', 'vm.runInContext'],
            'XSS': ['innerHTML', 'outerHTML', 'document.write', 'document.writeln'],
            'Prototype Pollution': ['_.merge', 'lodash.merge', 'Object.assign', 'extend'],
        },
        'go': {
            'Command Injection': ['os.exec', 'os.StartProcess', 'exec.Command', 'exec.CommandContext'],
            'Code Injection': ['eval', 'plugin.Open'],
            'SQL Injection': ['db.Query', 'db.QueryRow', 'db.Exec', 'db.Prepare',
                              'sql.DB.Query', 'sql.DB.Exec'],
            'SSRF': ['http.Get', 'http.Post', 'http.NewRequest', 'client.Do', 'urlfetch.Fetch'],
            'Path Traversal': ['os.Open', 'os.ReadFile', 'os.Create', 'os.OpenFile',
                               'ioutil.ReadFile', 'ioutil.WriteFile'],
            'Insecure Deserialization': ['json.Unmarshal', 'xml.Unmarshal', 'gob.Decode'],
            'XSS': ['template.Execute', 'html/template.Execute', 'fmt.Fprintf', 'io.WriteString'],
        },
    }

    # Safe functions that reduce taint
    SANITIZERS = {
        'python': ['sanitize', 'escape', 'html.escape', ' bleach.', 'validators.',
                   're.match', 're.search', 're.sub', 're.compile',
                   'ast.literal_eval', 'quote', 'quote_plus', 'urlencode',
                   'shlex.quote', 'pathlib.Path', 'os.path.abspath',
                   'validate', 'clean', 'strip', 'int(', 'float(', 'bool('],
        'javascript': ['sanitize', 'escape', 'DOMPurify', 'he.encode', 'validator.',
                       'encodeURIComponent', 'encodeURI', 'escapeHtml',
                       'lodash.escape', '_.escape'],
        'typescript': ['sanitize', 'escape', 'DOMPurify', 'he.encode', 'validator.',
                       'encodeURIComponent', 'encodeURI', 'escapeHtml'],
        'go': ['url.QueryEscape', 'html.EscapeString', 'template.HTMLEscapeString',
               'sanitize', 'validator.', 'regexp.MatchString', 'strconv.Atoi',
               'strconv.ParseInt', 'strconv.ParseFloat', 'path.Clean', 'filepath.Clean'],
    }

    # False positive patterns
    FP_PATTERNS = {
        'python': [
            r'ast\.literal_eval',
            r'json\.loads\s*\(',
            r'pickle\.loads\s*\(\s*safedata',
            r'#\s*SAFE\s*:',
        ],
        'javascript': [
            r'DOMPurify\.sanitize',
            r'he\.encode\s*\(',
            r'//\s*SAFE\s*:',
        ],
        'typescript': [
            r'DOMPurify\.sanitize',
            r'he\.encode\s*\(',
        ],
        'go': [
            r'//\s*SAFE\s*:',
        ],
    }

    def __init__(self):
        from tree_sitter import Language
        self.parsers = {}
        lang_mods = [
            ('python', tspython.language()),
            ('javascript', tsjs.language()),
            ('typescript', _get_ts_language('typescript')),
            ('go', tsgo.language()),
        ]
        for lang_name, lang_mod in lang_mods:
            try:
                lang = Language(lang_mod)
                self.parsers[lang_name] = Parser(lang)
            except Exception:
                pass

    def analyze_project(self, project_path: str, parsed_files: List, include_all: bool = False) -> List[TaintFlow]:
        """Analyze all files in project for taint flows."""
        flows = []
        file_map = {p.path: p for p in parsed_files}

        for pf in parsed_files:
            file_flows = self.analyze_file(pf)
            for flow in file_flows:
                # Cross-file: check if tainted variable flows into other files
                if flow.confidence == 'MEDIUM':
                    flow = self._check_cross_file(flow, pf, file_map)
                flows.append(flow)

        # Deduplicate by (file, line, sink_type)
        seen = set()
        unique_flows = []
        for flow in flows:
            key = (flow.sink.file, flow.sink.line, flow.sink.sink_type)
            if key not in seen:
                seen.add(key)
                unique_flows.append(flow)

        return unique_flows

    def analyze_file(self, file_result) -> List[TaintFlow]:
        """Analyze a single file for taint flows."""
        flows = []
        lang = file_result.language
        if lang not in self.parsers:
            return flows

        parser = self.parsers[lang]
        try:
            source_bytes = Path(file_result.path).read_bytes()
        except Exception:
            return flows

        tree = parser.parse(source_bytes)
        source_text = source_bytes.decode('utf-8', errors='replace')

        # Find sources and sinks in AST
        sources = self._find_sources(tree.root_node, lang, file_result.path, source_text)
        sinks = self._find_sinks(tree.root_node, lang, file_result.path, source_text)

        # Match sources to sinks via variable flow
        for source in sources:
            for sink in sinks:
                flow = self._trace_flow(source, sink, tree.root_node, lang, source_text)
                if flow:
                    flows.append(flow)

        return flows

    def _find_sources(self, node: Node, lang: str, filepath: str, source_text: str) -> List[TaintSource]:
        """Find all taint sources in the AST."""
        sources = []
        source_patterns = self.SOURCES.get(lang, set())

        for child in self._iter_nodes(node):
            text = child.text.decode('utf-8', errors='replace')
            for pattern in source_patterns:
                if pattern in text or re.search(re.escape(pattern) + r'\b', text):
                    source_type = 'EXTERNAL' if any(x in text for x in ['request', 'req.', 'req[']) else 'ENVIRONMENT'
                    if 'open(' in pattern or 'readFile' in pattern:
                        source_type = 'FILE'
                    sources.append(TaintSource(
                        name=text[:100],
                        line=child.start_point[0] + 1,
                        file=filepath,
                        source_type=source_type,
                    ))
                    break
        return sources

    def _find_sinks(self, node: Node, lang: str, filepath: str, source_text: str) -> List[TaintSink]:
        """Find all dangerous sinks in the AST."""
        sinks = []
        sink_categories = self.SINKS.get(lang, {})

        for child in self._iter_nodes(node):
            if child.type in ('call', 'call_expression', 'call_expression'):
                func_node = child.child_by_field_name('function')
                if not func_node:
                    continue
                func_text = func_node.text.decode('utf-8', errors='replace')

                for category, patterns in sink_categories.items():
                    for pattern in patterns:
                        if pattern in func_text or func_text.endswith(pattern.split('.')[-1]):
                            # Extract arguments
                            args = []
                            args_node = child.child_by_field_name('arguments')
                            if args_node:
                                for arg in args_node.children:
                                    if arg.type not in ('(', ')', ',', 'comment'):
                                        args.append(arg.text.decode('utf-8', errors='replace'))

                            sinks.append(TaintSink(
                                name=func_text,
                                line=child.start_point[0] + 1,
                                file=filepath,
                                sink_type=category,
                                arguments=args,
                            ))
                            break
        return sinks

    def _trace_flow(self, source: TaintSource, sink: TaintSink, root: Node, lang: str, source_text: str) -> Optional[TaintFlow]:
        """Trace if taint from source reaches sink with no sanitization."""
        # Quick reject: same line or source after sink
        if source.line == sink.line:
            return None
        if source.line > sink.line:
            return None

        # Check if source variable appears in sink arguments
        source_vars = self._extract_variables(source.name, lang)
        sink_args = ' '.join(sink.arguments)

        taint_reaches = any(var in sink_args for var in source_vars if len(var) > 1)

        # Also check if sink arguments contain any request-like patterns (direct passthrough)
        if not taint_reaches:
            if any(s in sink_args for s in ['request.', 'req.', 'input(', 'argv', 'environ']):
                taint_reaches = True

        if not taint_reaches:
            return None

        # Check for sanitizers between source and sink
        sanitizers = []
        source_node = self._find_node_at_line(root, source.line)
        sink_node = self._find_node_at_line(root, sink.line)

        if source_node and sink_node:
            region_text = self._get_text_between(source_node, sink_node, source_text)
            sanitizer_patterns = self.SANITIZERS.get(lang, [])
            for san in sanitizer_patterns:
                if san in region_text:
                    sanitizers.append(san)

        # Determine confidence
        if len(sanitizers) > 0:
            confidence = 'LOW'
        elif taint_reaches and len(source_vars) > 0:
            confidence = 'HIGH'
        else:
            confidence = 'MEDIUM'

        # False positive check
        if self._is_false_positive(sink, source_text, lang):
            return None

        # Calculate risk score
        risk = 0.9 if confidence == 'HIGH' else (0.6 if confidence == 'MEDIUM' else 0.3)
        if sink.sink_type in ('Command Injection', 'Insecure Deserialization', 'SQL Injection'):
            risk = min(1.0, risk + 0.1)
        if source.source_type == 'EXTERNAL':
            risk = min(1.0, risk + 0.1)
        if len(sanitizers) > 0:
            risk = max(0.0, risk - 0.3 * len(sanitizers))

        return TaintFlow(
            source=source,
            sink=sink,
            path=[f"{source.name} (line {source.line}) -> {sink.name} (line {sink.line})"],
            sanitizers=sanitizers,
            risk_score=risk,
            confidence=confidence,
        )

    def _check_cross_file(self, flow: TaintFlow, current_file, file_map: Dict) -> TaintFlow:
        """Check if tainted data flows to other files via function calls."""
        for other in file_map.values():
            if other.path == current_file.path:
                continue
            for func in other.functions:
                if flow.sink.name in func.calls or any(flow.sink.name in c for c in func.calls):
                    flow.path.append(f"-> {func.name} in {other.path}")
                    flow.confidence = 'HIGH'
        return flow

    def _extract_variables(self, source_text: str, lang: str) -> Set[str]:
        """Extract variable names from source code text."""
        # Simple heuristic: find identifiers
        if lang in ('python', 'javascript', 'typescript', 'go'):
            # Extract variable names (simple regex approach)
            vars_found = set(re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', source_text))
            # Filter out keywords
            keywords = {'if', 'else', 'for', 'while', 'return', 'def', 'function', 'class',
                        'import', 'from', 'try', 'except', 'catch', 'finally', 'var', 'let',
                        'const', 'true', 'false', 'null', 'undefined', 'None', 'True', 'False',
                        'self', 'this', 'super', 'new', 'delete', 'typeof', 'instanceof',
                        'in', 'of', 'async', 'await', 'yield', 'break', 'continue', 'pass',
                        'raise', 'throw', 'with', 'as', 'lambda', 'and', 'or', 'not', 'is',
                        'go', 'defer', 'range', 'select', 'switch', 'case', 'default',
                        'package', 'func', 'struct', 'interface', 'map', 'chan', 'goto'}
            return vars_found - keywords
        return set()

    def _find_node_at_line(self, node: Node, line: int) -> Optional[Node]:
        """Find AST node at a specific line."""
        if node.start_point[0] + 1 <= line <= node.end_point[0] + 1:
            return node
        for child in node.children:
            found = self._find_node_at_line(child, line)
            if found:
                return found
        return None

    def _get_text_between(self, start_node: Node, end_node: Node, source_text: str) -> str:
        """Get source text between two AST nodes."""
        start = start_node.start_byte
        end = end_node.end_byte
        return source_text[start:end]

    def _is_false_positive(self, sink: TaintSink, source_text: str, lang: str) -> bool:
        """Check if a sink is a known false positive."""
        fp_patterns = self.FP_PATTERNS.get(lang, [])
        for pattern in fp_patterns:
            if re.search(pattern, source_text):
                return True
        # Safe function whitelist
        safe_functions = {
            'python': ['ast.literal_eval', 'json.loads', 'pathlib.Path', 'shlex.quote'],
            'javascript': ['JSON.parse', 'encodeURIComponent', 'DOMPurify.sanitize'],
            'typescript': ['JSON.parse', 'encodeURIComponent', 'DOMPurify.sanitize'],
            'go': ['json.Unmarshal', 'html.EscapeString'],
        }
        for safe in safe_functions.get(lang, []):
            if safe in sink.name:
                return True
        return False

    def _iter_nodes(self, node: Node):
        """Iterate all nodes in tree."""
        yield node
        for child in node.children:
            yield from self._iter_nodes(child)
