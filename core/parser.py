"""ZeroCyber v7 — Tree-sitter based multi-language parser with call graph."""
import os
import re
import json
from typing import Dict, List, Set, Tuple, Optional, Any
from pathlib import Path
from dataclasses import dataclass, field
from concurrent.futures import ProcessPoolExecutor, as_completed

from tree_sitter import Language, Parser, Node

# Language bindings
import tree_sitter_python as tspython
import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts
import tree_sitter_go as tsgo


def _get_ts_language(lang_name: str):
    if lang_name == 'typescript':
        return tsts.language_typescript()
    else:
        return tsts.language_tsx()



@dataclass
class FunctionInfo:
    name: str
    start_line: int
    end_line: int
    parameters: List[str] = field(default_factory=list)
    calls: List[str] = field(default_factory=list)
    returns_tainted: bool = False


@dataclass
class FileParseResult:
    path: str
    language: str
    functions: List[FunctionInfo] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    global_vars: List[str] = field(default_factory=list)
    assignments: List[Dict] = field(default_factory=list)
    loc: int = 0


class LanguageParser:
    """Parse source files into AST and extract structural information."""

    LANGUAGES = {
        '.py': ('python', tspython.language()),
        '.js': ('javascript', tsjs.language()),
        '.jsx': ('javascript', tsjs.language()),
        '.ts': ('typescript', _get_ts_language('typescript')),
        '.tsx': ('typescript', _get_ts_language('tsx')),
        '.go': ('go', tsgo.language()),
    }

    def __init__(self):
        self.parsers: Dict[str, Parser] = {}
        for ext, (lang_name, lang_mod) in self.LANGUAGES.items():
            try:
                lang = Language(lang_mod)
                self.parsers[lang_name] = Parser(lang)
            except Exception:
                pass

    def parse_file(self, filepath: str) -> Optional[FileParseResult]:
        """Parse a single file and return structural information."""
        path = Path(filepath)
        ext = path.suffix.lower()
        if ext not in self.LANGUAGES:
            return None

        lang_name = self.LANGUAGES[ext][0]
        parser = self.parsers.get(lang_name)
        if not parser:
            return None

        try:
            source_bytes = path.read_bytes()
            source_text = source_bytes.decode('utf-8', errors='replace')
        except Exception:
            return None

        tree = parser.parse(source_bytes)
        root = tree.root_node

        result = FileParseResult(
            path=str(path.resolve()),
            language=lang_name,
            loc=len(source_text.splitlines()),
        )

        self._walk_tree(root, result, lang_name)
        return result

    def _walk_tree(self, node: Node, result: FileParseResult, lang: str):
        """Recursively walk AST and extract relevant nodes."""
        if node is None:
            return

        if lang == 'python':
            self._process_python_node(node, result)
        elif lang == 'javascript':
            self._process_js_node(node, result)
        elif lang == 'typescript':
            self._process_js_node(node, result)
        elif lang == 'go':
            self._process_go_node(node, result)

        for child in node.children:
            self._walk_tree(child, result, lang)

    def _process_python_node(self, node: Node, result: FileParseResult):
        if node.type == 'function_definition':
            func = self._extract_python_function(node)
            if func:
                result.functions.append(func)
        elif node.type == 'import_statement' or node.type == 'import_from_statement':
            result.imports.append(node.text.decode('utf-8', errors='replace'))
        elif node.type == 'assignment':
            self._extract_assignment(node, result)

    def _extract_python_function(self, node: Node) -> Optional[FunctionInfo]:
        name_node = node.child_by_field_name('name')
        if not name_node:
            return None
        name = name_node.text.decode('utf-8', errors='replace')

        params_node = node.child_by_field_name('parameters')
        params = []
        if params_node:
            for child in params_node.children:
                if child.type in ('identifier', 'default_parameter', 'typed_parameter'):
                    text = child.text.decode('utf-8', errors='replace').split('=')[0].split(':')[0].strip()
                    if text and text != 'self':
                        params.append(text)

        # Find calls inside function
        calls = []
        for child in self._iter_descendants(node):
            if child.type == 'call':
                func_node = child.child_by_field_name('function')
                if func_node:
                    call_name = func_node.text.decode('utf-8', errors='replace')
                    calls.append(call_name)

        # Check if returns tainted (simple heuristic)
        returns_tainted = any(
            'request' in c or 'input' in c or 'argv' in c or 'environ' in c
            for c in calls
        )

        return FunctionInfo(
            name=name,
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            parameters=params,
            calls=list(set(calls)),
            returns_tainted=returns_tainted,
        )

    def _process_js_node(self, node: Node, result: FileParseResult):
        if node.type in ('function_declaration', 'function_expression', 'arrow_function', 'method_definition'):
            func = self._extract_js_function(node)
            if func:
                result.functions.append(func)
        elif node.type in ('import_statement', 'import_declaration', 'require_call'):
            result.imports.append(node.text.decode('utf-8', errors='replace'))
        elif node.type == 'variable_declaration' or node.type == 'assignment_expression':
            self._extract_assignment(node, result)

    def _extract_js_function(self, node: Node) -> Optional[FunctionInfo]:
        name = None
        if node.type == 'function_declaration':
            name_node = node.child_by_field_name('name')
            if name_node:
                name = name_node.text.decode('utf-8', errors='replace')
        elif node.type == 'method_definition':
            name_node = node.child_by_field_name('name')
            if name_node:
                name = name_node.text.decode('utf-8', errors='replace')

        if not name:
            name = '<anonymous>'

        params = []
        params_node = node.child_by_field_name('parameters')
        if params_node:
            for child in params_node.children:
                if child.type in ('identifier', 'formal_parameter'):
                    text = child.text.decode('utf-8', errors='replace').split('=')[0].strip()
                    if text:
                        params.append(text)

        calls = []
        for child in self._iter_descendants(node):
            if child.type == 'call_expression':
                func_node = child.child_by_field_name('function')
                if func_node:
                    call_name = func_node.text.decode('utf-8', errors='replace')
                    calls.append(call_name)

        returns_tainted = any(
            'req' in c or 'request' in c or 'process.env' in c or 'argv' in c
            for c in calls
        )

        return FunctionInfo(
            name=name,
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            parameters=params,
            calls=list(set(calls)),
            returns_tainted=returns_tainted,
        )

    def _process_go_node(self, node: Node, result: FileParseResult):
        if node.type == 'function_declaration':
            func = self._extract_go_function(node)
            if func:
                result.functions.append(func)
        elif node.type == 'import_declaration':
            result.imports.append(node.text.decode('utf-8', errors='replace'))

    def _extract_go_function(self, node: Node) -> Optional[FunctionInfo]:
        name_node = node.child_by_field_name('name')
        if not name_node:
            return None
        name = name_node.text.decode('utf-8', errors='replace')

        params = []
        params_node = node.child_by_field_name('parameters')
        if params_node:
            for child in self._iter_descendants(params_node):
                if child.type == 'parameter_declaration':
                    for c in child.children:
                        if c.type == 'identifier':
                            text = c.text.decode('utf-8', errors='replace')
                            if text:
                                params.append(text)

        calls = []
        body = node.child_by_field_name('body')
        if body:
            for child in self._iter_descendants(body):
                if child.type == 'call_expression':
                    func_node = child.child_by_field_name('function')
                    if func_node:
                        call_name = func_node.text.decode('utf-8', errors='replace')
                        calls.append(call_name)

        returns_tainted = any(
            'r.URL' in c or 'FormValue' in c or 'os.Args' in c or 'os.Getenv' in c
            for c in calls
        )

        return FunctionInfo(
            name=name,
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            parameters=params,
            calls=list(set(calls)),
            returns_tainted=returns_tainted,
        )

    def _extract_assignment(self, node: Node, result: FileParseResult):
        text = node.text.decode('utf-8', errors='replace')
        result.assignments.append({
            'text': text,
            'line': node.start_point[0] + 1,
            'type': node.type,
        })

    def _iter_descendants(self, node: Node):
        """Iterate over all descendants of a node (excluding node itself)."""
        for child in node.children:
            yield child
            yield from self._iter_descendants(child)


class CallGraph:
    """Build cross-file call graph from parsed results."""

    def __init__(self):
        self.files: Dict[str, FileParseResult] = {}
        self.function_index: Dict[str, List[str]] = {}  # name -> [file paths]
        self.call_edges: List[Tuple[str, str, str]] = []  # (from_file, from_func, to_func)

    def add_file(self, result: FileParseResult):
        self.files[result.path] = result
        for func in result.functions:
            self.function_index.setdefault(func.name, []).append(result.path)

    def build(self):
        """Build call edges between functions across files."""
        self.call_edges = []
        for path, result in self.files.items():
            for func in result.functions:
                for call in func.calls:
                    call_name = call.split('.')[-1]  # module.func -> func
                    if call_name in self.function_index:
                        for target_path in self.function_index[call_name]:
                            self.call_edges.append((path, func.name, call_name))

    def find_paths(self, source_func: str, sink_func: str, max_depth: int = 5) -> List[List[str]]:
        """Find call paths from source to sink."""
        paths = []
        visited = set()

        def dfs(current: str, path: List[str], depth: int):
            if depth > max_depth:
                return
            if current == sink_func:
                paths.append(path[:])
                return
            if current in visited:
                return
            visited.add(current)

            for _, from_f, to_f in self.call_edges:
                if from_f == current:
                    path.append(to_f)
                    dfs(to_f, path, depth + 1)
                    path.pop()

            visited.discard(current)

        dfs(source_func, [source_func], 0)
        return paths


def scan_project(project_path: str, include_all: bool = False, max_workers: int = 8) -> Tuple[List[FileParseResult], CallGraph]:
    """Scan all source files in a project and build call graph."""
    parser = LanguageParser()
    results = []

    # Determine exclusions
    EXCLUDED_DIRS = {'node_modules', '.git', '__pycache__', 'venv', '.venv', 'env', 'dist', 'build'}
    if not include_all:
        EXCLUDED_DIRS |= {'test', 'tests', 'testing', 'spec', 'docs', 'doc', 'example', 'examples'}

    EXTENSIONS = set(LanguageParser.LANGUAGES.keys())

    all_files = []
    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for f in files:
            if any(f.endswith(ext) for ext in EXTENSIONS):
                all_files.append(os.path.join(root, f))

    total_files = len(all_files)
    parsed = 0

    # Use process pool for parallel parsing if enough files
    if total_files > 50 and max_workers > 1:
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(parser.parse_file, fp): fp for fp in all_files}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                parsed += 1
    else:
        for fp in all_files:
            result = parser.parse_file(fp)
            if result:
                results.append(result)
            parsed += 1

    # Build call graph
    call_graph = CallGraph()
    for r in results:
        call_graph.add_file(r)
    call_graph.build()

    return results, call_graph, total_files, parsed
