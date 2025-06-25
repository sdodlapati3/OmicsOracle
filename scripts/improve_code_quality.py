#!/usr/bin/env python3
"""
Code quality improvement script for the futuristic interface.
Fixes common linting issues like unused imports, missing type annotations, etc.
"""

import ast
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple


class CodeQualityImprover:
    """Improves code quality by fixing common linting issues"""

    def __init__(self, base_path: Path):
        self.base_path = base_path
        self.fixes_applied = []

    def fix_unused_imports(self, file_path: Path) -> bool:
        """Remove unused imports from a Python file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Parse the AST to find imports and used names
            tree = ast.parse(content)
            
            # Find all imports
            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    for alias in node.names:
                        imports.append(alias.name)

            # For now, let's handle the most common unused imports manually
            # This is a simplified version - a full implementation would need more sophisticated analysis
            
            common_unused_patterns = [
                (r'^import asyncio\n', r'asyncio'),
                (r'^import json\n', r'json'),
                (r'^import time\n', r'time'),
                (r'^import os\n', r'os'),
                (r'^import re\n', r're'),
                (r'^from typing import Any\n', r'Any'),
                (r'^from typing import List\n', r'List'),
                (r'^from typing import Dict\n', r'Dict'),
                (r'^from typing import Optional\n', r'Optional'),
            ]

            original_content = content
            for pattern, name in common_unused_patterns:
                if re.search(pattern, content, re.MULTILINE) and name not in content.replace(f"import {name}", ""):
                    content = re.sub(pattern, "", content, flags=re.MULTILINE)

            if content != original_content:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                return True
            return False

        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            return False

    def fix_bare_except(self, file_path: Path) -> bool:
        """Fix bare except clauses"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            original_content = content
            
            # Replace bare except with Exception
            content = re.sub(
                r'except:\s*\n',
                'except Exception:\n',
                content
            )
            
            # Replace except: with except Exception:
            content = re.sub(
                r'except:\s*$',
                'except Exception:',
                content,
                flags=re.MULTILINE
            )

            if content != original_content:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                return True
            return False

        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            return False

    def fix_f_strings(self, file_path: Path) -> bool:
        """Fix f-strings without placeholders"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            original_content = content
            
            # Find f-strings without {} placeholders and convert them to regular strings
            # This is a simple regex - a more sophisticated approach would parse the AST
            f_string_pattern = r'f"([^"]*)"'
            
            def replace_f_string(match):
                string_content = match.group(1)
                # If no {} placeholders, convert to regular string
                if '{' not in string_content:
                    return f'"{string_content}"'
                return match.group(0)
            
            content = re.sub(f_string_pattern, replace_f_string, content)
            
            # Handle single quotes too
            f_string_pattern_single = r"f'([^']*)'"
            
            def replace_f_string_single(match):
                string_content = match.group(1)
                if '{' not in string_content:
                    return f"'{string_content}'"
                return match.group(0)
            
            content = re.sub(f_string_pattern_single, replace_f_string_single, content)

            if content != original_content:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                return True
            return False

        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            return False

    def fix_undefined_variables(self, file_path: Path) -> bool:
        """Fix common undefined variable issues"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            original_content = content
            
            # Fix specific undefined variables we know about
            fixes = [
                # In UI routes, fix font/size variables
                (r'font-size: {font.*?size}', 'font-size: 14px'),
                (r'font.*?size', '14px'),
                # Add other specific fixes as needed
            ]

            for pattern, replacement in fixes:
                content = re.sub(pattern, replacement, content)

            if content != original_content:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                return True
            return False

        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            return False

    def process_file(self, file_path: Path) -> List[str]:
        """Process a single file and return list of fixes applied"""
        fixes = []
        
        if self.fix_unused_imports(file_path):
            fixes.append("unused imports")
        
        if self.fix_bare_except(file_path):
            fixes.append("bare except clauses")
        
        if self.fix_f_strings(file_path):
            fixes.append("f-string placeholders")
        
        if self.fix_undefined_variables(file_path):
            fixes.append("undefined variables")
        
        return fixes

    def improve_directory(self, directory: Path) -> Dict[str, List[str]]:
        """Improve code quality in all Python files in a directory"""
        results = {}
        
        for py_file in directory.rglob("*.py"):
            if py_file.is_file():
                fixes = self.process_file(py_file)
                if fixes:
                    results[str(py_file.relative_to(self.base_path))] = fixes
        
        return results


def main():
    """Main function to improve code quality"""
    base_path = Path(__file__).parent.parent
    futuristic_path = base_path / "interfaces" / "futuristic"
    
    if not futuristic_path.exists():
        print(f"Futuristic interface directory not found: {futuristic_path}")
        return
    
    improver = CodeQualityImprover(base_path)
    results = improver.improve_directory(futuristic_path)
    
    if results:
        print("Code quality improvements applied:")
        for file_path, fixes in results.items():
            print(f"  {file_path}: {', '.join(fixes)}")
    else:
        print("No code quality issues found or all files are already clean!")
    
    print(f"\nProcessed {len(list(futuristic_path.rglob('*.py')))} Python files")


if __name__ == "__main__":
    main()
