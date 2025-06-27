#!/usr/bin/env python3
"""
Architecture Quality Assessment Tool for OmicsOracle

This script provides automated analysis of architectural quality metrics,
including coupling, cohesion, complexity, and adherence to clean architecture principles.
"""

import ast
import json
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import networkx as nx


@dataclass
class FileMetrics:
    """Metrics for a single Python file."""

    path: str
    lines_of_code: int
    cyclomatic_complexity: int
    imports: List[str] = field(default_factory=list)
    classes: List[str] = field(default_factory=list)
    functions: List[str] = field(default_factory=list)
    sys_path_usage: int = 0
    god_class_score: float = 0.0


@dataclass
class ComponentMetrics:
    """Metrics for a component/module."""

    name: str
    files: List[str] = field(default_factory=list)
    total_loc: int = 0
    average_complexity: float = 0.0
    coupling_score: float = 0.0
    cohesion_score: float = 0.0
    architectural_violations: List[str] = field(default_factory=list)


@dataclass
class ArchitecturalAnalysis:
    """Complete architectural analysis results."""

    total_files: int = 0
    total_loc: int = 0
    circular_dependencies: List[Tuple[str, str]] = field(default_factory=list)
    sys_path_violations: int = 0
    god_files: List[str] = field(default_factory=list)
    architectural_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)


class PythonASTAnalyzer(ast.NodeVisitor):
    """AST visitor for analyzing Python code quality metrics."""

    def __init__(self):
        self.complexity = 0
        self.imports = []
        self.classes = []
        self.functions = []
        self.sys_path_usage = 0
        self.current_class = None
        self.class_methods = defaultdict(list)

    def visit_Import(self, node):
        for alias in node.names:
            self.imports.append(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            self.imports.append(node.module)
        self.generic_visit(node)

    def visit_Call(self, node):
        # Check for sys.path manipulations
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Attribute)
            and isinstance(node.func.value.value, ast.Name)
            and node.func.value.value.id == "sys"
            and node.func.value.attr == "path"
            and node.func.attr in ["insert", "append"]
        ):
            self.sys_path_usage += 1
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self.functions.append(node.name)
        if self.current_class:
            self.class_methods[self.current_class].append(node.name)

        # Calculate cyclomatic complexity
        self.complexity += 1  # Base complexity
        self._calculate_complexity(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node):
        self.classes.append(node.name)
        old_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = old_class

    def _calculate_complexity(self, node):
        """Calculate cyclomatic complexity for a function."""
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                self.complexity += 1
            elif isinstance(child, (ast.ExceptHandler,)):
                self.complexity += 1
            elif isinstance(child, ast.BoolOp):
                self.complexity += len(child.values) - 1


class ArchitecturalAnalyzer:
    """Main analyzer for architectural quality assessment."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.file_metrics: Dict[str, FileMetrics] = {}
        self.component_metrics: Dict[str, ComponentMetrics] = {}
        self.dependency_graph = nx.DiGraph()

    def analyze_project(self) -> ArchitecturalAnalysis:
        """Perform comprehensive architectural analysis."""
        print("🔍 Starting architectural analysis...")

        # Analyze all Python files
        self._analyze_files()

        # Build dependency graph
        self._build_dependency_graph()

        # Analyze components
        self._analyze_components()

        # Generate overall analysis
        analysis = self._generate_analysis()

        print(f"✅ Analysis complete. Analyzed {analysis.total_files} files.")
        return analysis

    def _analyze_files(self):
        """Analyze all Python files in the project."""
        src_patterns = ["src/**/*.py", "interfaces/**/*.py", "tests/**/*.py"]

        for pattern in src_patterns:
            for file_path in self.project_root.glob(pattern):
                if file_path.is_file() and not file_path.name.startswith("__"):
                    self._analyze_file(file_path)

    def _analyze_file(self, file_path: Path):
        """Analyze a single Python file."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Count lines of code (excluding comments and empty lines)
            lines = content.split("\n")
            loc = len(
                [
                    line
                    for line in lines
                    if line.strip() and not line.strip().startswith("#")
                ]
            )

            # Parse AST
            tree = ast.parse(content)
            analyzer = PythonASTAnalyzer()
            analyzer.visit(tree)

            # Calculate god class score
            god_class_score = self._calculate_god_class_score(
                analyzer.class_methods
            )

            # Store metrics
            relative_path = str(file_path.relative_to(self.project_root))
            self.file_metrics[relative_path] = FileMetrics(
                path=relative_path,
                lines_of_code=loc,
                cyclomatic_complexity=analyzer.complexity,
                imports=analyzer.imports,
                classes=analyzer.classes,
                functions=analyzer.functions,
                sys_path_usage=analyzer.sys_path_usage,
                god_class_score=god_class_score,
            )

        except Exception as e:
            print(f"⚠️  Error analyzing {file_path}: {e}")

    def _calculate_god_class_score(
        self, class_methods: Dict[str, List[str]]
    ) -> float:
        """Calculate god class score based on number of methods."""
        if not class_methods:
            return 0.0

        max_methods = max(len(methods) for methods in class_methods.values())

        # Score based on method count (higher is worse)
        if max_methods > 50:
            return 10.0  # Definitely a god class
        elif max_methods > 30:
            return 7.0
        elif max_methods > 20:
            return 5.0
        elif max_methods > 10:
            return 3.0
        else:
            return 1.0

    def _build_dependency_graph(self):
        """Build dependency graph from import relationships."""
        for file_path, metrics in self.file_metrics.items():
            # Add node for this file
            self.dependency_graph.add_node(file_path)

            # Add edges for imports
            for import_name in metrics.imports:
                # Try to resolve import to actual file
                resolved_path = self._resolve_import(import_name, file_path)
                if resolved_path and resolved_path in self.file_metrics:
                    self.dependency_graph.add_edge(file_path, resolved_path)

    def _resolve_import(self, import_name: str, from_file: str) -> str:
        """Resolve import name to actual file path."""
        # Simplified import resolution
        if import_name.startswith("src.omics_oracle"):
            # Convert to file path
            parts = import_name.split(".")
            if len(parts) > 2:
                path_parts = parts[2:]  # Skip 'src.omics_oracle'
                potential_path = Path("src/omics_oracle") / "/".join(path_parts)

                # Try .py file
                py_file = potential_path.with_suffix(".py")
                if (self.project_root / py_file).exists():
                    return str(py_file)

                # Try __init__.py in directory
                init_file = potential_path / "__init__.py"
                if (self.project_root / init_file).exists():
                    return str(init_file)

        return None

    def _analyze_components(self):
        """Analyze components/modules for coupling and cohesion."""
        # Group files by component (top-level directory under src)
        components = defaultdict(list)

        for file_path in self.file_metrics.keys():
            if file_path.startswith("src/omics_oracle/"):
                parts = file_path.split("/")
                if len(parts) >= 3:
                    component = parts[2]  # e.g., 'pipeline', 'services'
                    components[component].append(file_path)

        # Calculate component metrics
        for component_name, files in components.items():
            metrics = ComponentMetrics(name=component_name, files=files)

            # Calculate totals
            metrics.total_loc = sum(
                self.file_metrics[f].lines_of_code for f in files
            )

            # Calculate average complexity
            complexities = [
                self.file_metrics[f].cyclomatic_complexity for f in files
            ]
            metrics.average_complexity = (
                sum(complexities) / len(complexities) if complexities else 0
            )

            # Calculate coupling (simplified)
            metrics.coupling_score = self._calculate_coupling(files)

            # Calculate cohesion (simplified)
            metrics.cohesion_score = self._calculate_cohesion(files)

            # Identify violations
            metrics.architectural_violations = self._identify_violations(files)

            self.component_metrics[component_name] = metrics

    def _calculate_coupling(self, files: List[str]) -> float:
        """Calculate coupling score for a component."""
        # Count external dependencies
        external_deps = set()
        for file_path in files:
            metrics = self.file_metrics[file_path]
            for import_name in metrics.imports:
                if not import_name.startswith("src.omics_oracle"):
                    external_deps.add(import_name)

        # Higher external dependencies = higher coupling
        return min(len(external_deps) / 10.0, 10.0)  # Normalize to 0-10 scale

    def _calculate_cohesion(self, files: List[str]) -> float:
        """Calculate cohesion score for a component."""
        # Simplified cohesion based on internal dependencies
        internal_deps = 0
        total_possible = len(files) * (len(files) - 1)

        if total_possible == 0:
            return 10.0

        for file_path in files:
            for neighbor in self.dependency_graph.neighbors(file_path):
                if neighbor in files:
                    internal_deps += 1

        # Higher internal dependencies = higher cohesion
        cohesion = (
            (internal_deps / total_possible) * 10.0
            if total_possible > 0
            else 10.0
        )
        return min(cohesion, 10.0)

    def _identify_violations(self, files: List[str]) -> List[str]:
        """Identify architectural violations in component."""
        violations = []

        for file_path in files:
            metrics = self.file_metrics[file_path]

            # Check for violations
            if metrics.lines_of_code > 500:
                violations.append(
                    f"God file: {file_path} ({metrics.lines_of_code} LOC)"
                )

            if metrics.cyclomatic_complexity > 50:
                violations.append(
                    f"High complexity: {file_path} ({metrics.cyclomatic_complexity})"
                )

            if metrics.sys_path_usage > 0:
                violations.append(f"sys.path manipulation: {file_path}")

            if metrics.god_class_score > 7.0:
                violations.append(f"God class detected: {file_path}")

        return violations

    def _generate_analysis(self) -> ArchitecturalAnalysis:
        """Generate overall architectural analysis."""
        analysis = ArchitecturalAnalysis()

        # Basic statistics
        analysis.total_files = len(self.file_metrics)
        analysis.total_loc = sum(
            m.lines_of_code for m in self.file_metrics.values()
        )

        # Find circular dependencies
        try:
            cycles = list(nx.simple_cycles(self.dependency_graph))
            analysis.circular_dependencies = [
                (cycle[0], cycle[1]) for cycle in cycles[:10]
            ]  # Limit to 10
        except:
            analysis.circular_dependencies = []

        # Count violations
        analysis.sys_path_violations = sum(
            m.sys_path_usage for m in self.file_metrics.values()
        )
        analysis.god_files = [
            m.path for m in self.file_metrics.values() if m.lines_of_code > 500
        ]

        # Calculate architectural score
        analysis.architectural_score = self._calculate_architectural_score()

        # Generate recommendations (pass analysis object)
        analysis.recommendations = self._generate_recommendations(analysis)

        return analysis

    def _calculate_architectural_score(self) -> float:
        """Calculate overall architectural quality score (0-10)."""
        scores = []

        # File size score (penalize large files)
        avg_file_size = sum(
            m.lines_of_code for m in self.file_metrics.values()
        ) / len(self.file_metrics)
        size_score = max(
            0, 10 - (avg_file_size / 100)
        )  # Penalize files >1000 LOC heavily
        scores.append(size_score)

        # Complexity score
        avg_complexity = sum(
            m.cyclomatic_complexity for m in self.file_metrics.values()
        ) / len(self.file_metrics)
        complexity_score = max(0, 10 - (avg_complexity / 10))
        scores.append(complexity_score)

        # Coupling score (based on sys.path usage as proxy)
        sys_path_violations = sum(
            m.sys_path_usage for m in self.file_metrics.values()
        )
        coupling_score = max(0, 10 - (sys_path_violations / 10))
        scores.append(coupling_score)

        # Circular dependency score
        try:
            cycles = list(nx.simple_cycles(self.dependency_graph))
            cycle_count = len(cycles)
        except:
            cycle_count = 0
        cycle_score = max(0, 10 - cycle_count)
        scores.append(cycle_score)

        return sum(scores) / len(scores)

    def _generate_recommendations(
        self, analysis: ArchitecturalAnalysis
    ) -> List[str]:
        """Generate specific recommendations for improvement."""
        recommendations = []

        if analysis.sys_path_violations > 0:
            recommendations.append(
                f"🚨 CRITICAL: Remove {analysis.sys_path_violations} sys.path manipulations. "
                "Implement proper package structure."
            )

        if len(analysis.god_files) > 0:
            recommendations.append(
                f"📝 Refactor {len(analysis.god_files)} large files (>500 LOC): "
                f"{', '.join(analysis.god_files[:3])}{'...' if len(analysis.god_files) > 3 else ''}"
            )

        if len(analysis.circular_dependencies) > 0:
            recommendations.append(
                f"🔄 Break {len(analysis.circular_dependencies)} circular dependencies. "
                "Implement dependency inversion."
            )

        # Component-specific recommendations
        for name, component in self.component_metrics.items():
            if component.coupling_score > 7:
                recommendations.append(
                    f"🔗 Reduce coupling in {name} component (score: {component.coupling_score:.1f})"
                )

            if component.cohesion_score < 3:
                recommendations.append(
                    f"🎯 Improve cohesion in {name} component (score: {component.cohesion_score:.1f})"
                )

        return recommendations


def main():
    """Main entry point for architectural analysis."""
    project_root = Path.cwd()

    print("🏗️  OmicsOracle Architectural Quality Assessment")
    print("=" * 60)

    analyzer = ArchitecturalAnalyzer(project_root)
    analysis = analyzer.analyze_project()

    # Print results
    print(f"\n📊 ANALYSIS RESULTS")
    print(f"{'=' * 40}")
    print(f"Total Files Analyzed: {analysis.total_files}")
    print(f"Total Lines of Code: {analysis.total_loc:,}")
    print(f"Architectural Score: {analysis.architectural_score:.1f}/10")
    print(f"Circular Dependencies: {len(analysis.circular_dependencies)}")
    print(f"sys.path Violations: {analysis.sys_path_violations}")
    print(f"God Files (>500 LOC): {len(analysis.god_files)}")

    # Component analysis
    if analyzer.component_metrics:
        print(f"\n🏗️  COMPONENT ANALYSIS")
        print(f"{'=' * 40}")
        for name, component in analyzer.component_metrics.items():
            print(
                f"{name:15} | LOC: {component.total_loc:5,} | "
                f"Coupling: {component.coupling_score:.1f} | "
                f"Cohesion: {component.cohesion_score:.1f} | "
                f"Violations: {len(component.architectural_violations)}"
            )

    # Recommendations
    if analysis.recommendations:
        print(f"\n💡 RECOMMENDATIONS")
        print(f"{'=' * 40}")
        for i, rec in enumerate(analysis.recommendations[:10], 1):
            print(f"{i:2}. {rec}")

    # Save detailed report
    report_path = project_root / "docs" / "architecture_quality_report.json"
    report_path.parent.mkdir(exist_ok=True)

    report_data = {
        "analysis": {
            "total_files": analysis.total_files,
            "total_loc": analysis.total_loc,
            "architectural_score": analysis.architectural_score,
            "circular_dependencies": analysis.circular_dependencies,
            "sys_path_violations": analysis.sys_path_violations,
            "god_files": analysis.god_files,
            "recommendations": analysis.recommendations,
        },
        "file_metrics": {
            path: {
                "lines_of_code": metrics.lines_of_code,
                "cyclomatic_complexity": metrics.cyclomatic_complexity,
                "sys_path_usage": metrics.sys_path_usage,
                "god_class_score": metrics.god_class_score,
                "imports_count": len(metrics.imports),
                "classes_count": len(metrics.classes),
                "functions_count": len(metrics.functions),
            }
            for path, metrics in analyzer.file_metrics.items()
        },
        "component_metrics": {
            name: {
                "total_loc": component.total_loc,
                "average_complexity": component.average_complexity,
                "coupling_score": component.coupling_score,
                "cohesion_score": component.cohesion_score,
                "violations": component.architectural_violations,
            }
            for name, component in analyzer.component_metrics.items()
        },
    }

    with open(report_path, "w") as f:
        json.dump(report_data, f, indent=2)

    print(f"\n📄 Detailed report saved to: {report_path}")

    # Return exit code based on quality
    if analysis.architectural_score < 5:
        print(
            f"\n❌ POOR ARCHITECTURAL QUALITY (Score: {analysis.architectural_score:.1f}/10)"
        )
        print("   Immediate refactoring recommended!")
        return 1
    elif analysis.architectural_score < 7:
        print(
            f"\n⚠️  MODERATE ARCHITECTURAL QUALITY (Score: {analysis.architectural_score:.1f}/10)"
        )
        print("   Improvement needed.")
        return 0
    else:
        print(
            f"\n✅ GOOD ARCHITECTURAL QUALITY (Score: {analysis.architectural_score:.1f}/10)"
        )
        return 0


if __name__ == "__main__":
    exit(main())
