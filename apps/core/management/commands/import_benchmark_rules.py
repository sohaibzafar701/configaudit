"""
Django management command to import benchmark rules from scripts/populate_benchmark_rules.py
"""
import sys
import ast
from pathlib import Path
from django.core.management.base import BaseCommand
from apps.core.models import Rule


class Command(BaseCommand):
    help = 'Import benchmark rules from scripts/populate_benchmark_rules.py into Django database'

    def add_arguments(self, parser):
        parser.add_argument(
            '--skip-existing',
            action='store_true',
            help='Skip rules that already exist (by name)',
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Delete all existing rules before importing',
        )

    def handle(self, *args, **options):
        skip_existing = options['skip_existing']
        force = options['force']
        
        if force:
            self.stdout.write('Deleting all existing rules...')
            count = Rule.objects.count()
            Rule.objects.all().delete()
            self.stdout.write(self.style.WARNING(f'Deleted {count} existing rules.'))
        
        # Path calculation
        project_root = Path(__file__).parent.parent.parent.parent.parent
        scripts_path = project_root / 'scripts' / 'populate_benchmark_rules.py'
        
        if not scripts_path.exists():
            self.stdout.write(
                self.style.ERROR(f'Could not find {scripts_path}')
            )
            return
        
        try:
            # Read and parse the source file
            with open(scripts_path, 'r') as f:
                source_code = f.read()
            
            # Extract rules using AST
            rules = self._extract_rules_from_source(source_code)
            
            if not rules:
                self.stdout.write(
                    self.style.ERROR('Could not extract rules from populate_benchmark_rules.py')
                )
                return
            
            self.stdout.write(f'Found {len(rules)} benchmark rules to import...')
            
            created_count = 0
            skipped_count = 0
            error_count = 0
            
            for i, rule_data in enumerate(rules, 1):
                name = rule_data.get('name', 'Unnamed Rule')
                
                # Check if rule exists
                if skip_existing and Rule.objects.filter(name=name).exists():
                    skipped_count += 1
                    if i % 10 == 0:
                        self.stdout.write(f'Progress: {i}/{len(rules)} (skipped: {skipped_count})')
                    continue
                
                try:
                    # Convert tags list to string
                    tags = rule_data.get('tags', ['cisco', 'all'])
                    if isinstance(tags, list):
                        tags_str = ','.join(str(t) for t in tags)
                    else:
                        tags_str = str(tags) if tags else 'cisco,all'
                    
                    # Create rule using Django model
                    Rule.objects.create(
                        name=name,
                        description=rule_data.get('description', ''),
                        rule_type=rule_data.get('rule_type', 'pattern'),
                        category=rule_data.get('category', 'Network Security'),
                        severity=rule_data.get('severity', 'medium'),
                        yaml_content=rule_data.get('yaml_content', ''),
                        tags=tags_str,
                        remediation_template=rule_data.get('remediation_template', ''),
                        compliance_frameworks=rule_data.get('compliance_frameworks', ''),
                        framework_mappings=rule_data.get('framework_mappings'),
                        risk_weight=rule_data.get('risk_weight', 1.0),
                        enabled=True
                    )
                    created_count += 1
                    
                    if i % 10 == 0:
                        self.stdout.write(f'Progress: {i}/{len(rules)} (created: {created_count}, skipped: {skipped_count})')
                        
                except Exception as e:
                    error_count += 1
                    self.stdout.write(
                        self.style.ERROR(f'Error creating rule "{name}": {str(e)}')
                    )
            
            # Summary
            self.stdout.write('')
            self.stdout.write(self.style.SUCCESS('=' * 60))
            self.stdout.write(self.style.SUCCESS('Import Summary:'))
            self.stdout.write(self.style.SUCCESS(f'  Total rules processed: {len(rules)}'))
            self.stdout.write(self.style.SUCCESS(f'  Created: {created_count}'))
            if skipped_count > 0:
                self.stdout.write(self.style.WARNING(f'  Skipped (already exist): {skipped_count}'))
            if error_count > 0:
                self.stdout.write(self.style.ERROR(f'  Errors: {error_count}'))
            self.stdout.write(self.style.SUCCESS('=' * 60))
            
            total_in_db = Rule.objects.count()
            self.stdout.write(self.style.SUCCESS(f'\nTotal rules in database: {total_in_db}'))
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error importing benchmark rules: {str(e)}')
            )
            import traceback
            self.stdout.write(traceback.format_exc())
    
    def _extract_rules_from_source(self, source_code):
        """Extract rules list from source code using AST"""
        try:
            tree = ast.parse(source_code)
            rules = []
            
            # Find the populate_benchmark_rules function
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == 'populate_benchmark_rules':
                    # Find the rules = [...] assignment
                    for stmt in node.body:
                        if isinstance(stmt, ast.Assign):
                            for target in stmt.targets:
                                if isinstance(target, ast.Name) and target.id == 'rules':
                                    if isinstance(stmt.value, ast.List):
                                        # Convert AST list to Python list
                                        for elt in stmt.value.elts:
                                            if isinstance(elt, ast.Dict):
                                                rule_dict = {}
                                                for key_node, value_node in zip(elt.keys, elt.values):
                                                    # Extract key
                                                    if isinstance(key_node, ast.Constant):
                                                        key_str = key_node.value
                                                    elif isinstance(key_node, ast.Str):  # Python < 3.8
                                                        key_str = key_node.s
                                                    else:
                                                        continue
                                                    
                                                    # Extract value
                                                    val = self._extract_ast_value(value_node)
                                                    rule_dict[key_str] = val
                                                
                                                if rule_dict:
                                                    rules.append(rule_dict)
                                        break
                    break
            
            return rules
        except Exception as e:
            self.stdout.write(self.style.WARNING(f'AST extraction failed: {e}'))
            # Fallback: try regex-based extraction
            return self._extract_rules_regex(source_code)
    
    def _extract_ast_value(self, node):
        """Extract value from AST node"""
        if isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.Str):  # Python < 3.8
            return node.s
        elif isinstance(node, ast.Num):  # Python < 3.8
            return node.n
        elif isinstance(node, ast.NameConstant):  # Python < 3.8
            return node.value
        elif isinstance(node, ast.List):
            return [self._extract_ast_value(v) for v in node.elts]
        elif isinstance(node, ast.Attribute):
            # Handle Rule.TYPE_PATTERN, Rule.TYPE_PYTHON, etc.
            if hasattr(node, 'value') and isinstance(node.value, ast.Name):
                if node.value.id == 'Rule' and hasattr(node, 'attr'):
                    # Map to Rule constants
                    attr_map = {
                        'TYPE_PATTERN': 'pattern',
                        'TYPE_PYTHON': 'python',
                        'TYPE_HYBRID': 'hybrid'
                    }
                    return attr_map.get(node.attr, 'pattern')
        elif isinstance(node, ast.JoinedStr):  # f-strings
            # For f-strings, just return a placeholder or try to reconstruct
            parts = []
            for part in node.values:
                if isinstance(part, ast.Constant):
                    parts.append(str(part.value))
                elif isinstance(part, ast.Str):
                    parts.append(part.s)
                else:
                    parts.append('{...}')
            return ''.join(parts)
        
        # For complex expressions, return a string representation
        return str(node)
    
    def _extract_rules_regex(self, source_code):
        """Fallback: Extract rules using regex (less reliable but simpler)"""
        import re
        import json
        
        rules = []
        
        # Find all rule dictionaries in the source
        # Look for patterns like {"name": "...", "description": "...", ...}
        # This is a simplified approach
        rule_pattern = r'\{\s*"name"\s*:\s*"([^"]+)"'
        
        # More comprehensive: find the rules list block
        match = re.search(r'rules\s*=\s*\[', source_code, re.MULTILINE)
        if match:
            # Try to extract the list content
            # This is complex, so we'll use a simpler approach:
            # Execute the script in a controlled environment
            
            # Create a safe execution environment
            safe_globals = {
                '__builtins__': __builtins__,
                'Rule': type('Rule', (), {
                    'TYPE_PATTERN': 'pattern',
                    'TYPE_PYTHON': 'python',
                    'TYPE_HYBRID': 'hybrid'
                })(),
            }
            
            # Try to extract just the rules list by finding it and evaluating
            # Find the start of rules = [
            start_idx = source_code.find('rules = [')
            if start_idx != -1:
                # Find matching closing bracket
                bracket_count = 0
                in_string = False
                escape = False
                string_char = None
                i = start_idx + len('rules = [')
                
                while i < len(source_code):
                    char = source_code[i]
                    
                    if escape:
                        escape = False
                        i += 1
                        continue
                    
                    if char == '\\':
                        escape = True
                        i += 1
                        continue
                    
                    if not in_string:
                        if char == '[':
                            bracket_count += 1
                        elif char == ']':
                            bracket_count -= 1
                            if bracket_count == -1:
                                # Found the closing bracket for rules = [...]
                                rules_str = source_code[start_idx:i+1]
                                # Replace Rule.TYPE_* with strings
                                rules_str = rules_str.replace('Rule.TYPE_PATTERN', '"pattern"')
                                rules_str = rules_str.replace('Rule.TYPE_PYTHON', '"python"')
                                rules_str = rules_str.replace('Rule.TYPE_HYBRID', '"hybrid"')
                                
                                try:
                                    # Evaluate in safe environment
                                    rules = eval(rules_str, safe_globals)
                                    if isinstance(rules, list):
                                        return rules
                                except Exception as e:
                                    self.stdout.write(self.style.WARNING(f'Regex extraction also failed: {e}'))
                                break
                    else:
                        if char == string_char:
                            in_string = False
                            string_char = None
                    
                    if not in_string and char in ('"', "'"):
                        in_string = True
                        string_char = char
                    
                    i += 1
        
        return rules
