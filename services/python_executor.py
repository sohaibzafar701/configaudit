"""
Python rule executor - executes Python rules in separate subprocess
"""

import subprocess
import json
import tempfile
import os

def execute_python_rule_safe(rule, parsed_config):
    """Execute Python rule in separate subprocess for security"""
    findings = []
    
    try:
        # Parse YAML content from rule
        import yaml
        rule_yaml = yaml.safe_load(rule.get('yaml_content', ''))
        
        # Create temporary script file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            # Write rule execution script
            # Extract Python code from YAML rule
            python_code = rule_yaml.get('python', '') if rule_yaml else ''
            
            script_content = f"""
import json
import sys

# Read config from stdin
config_json = sys.stdin.read()
config = json.loads(config_json)

# Rule execution code
findings = []

{python_code}

# Output findings as JSON
print(json.dumps(findings))
"""
            f.write(script_content)
            script_path = f.name
        
        try:
            # Execute in subprocess with timeout
            config_json = json.dumps(parsed_config)
            
            result = subprocess.run(
                ['python', script_path],
                input=config_json,
                capture_output=True,
                text=True,
                timeout=30  # 30 second timeout
            )
            
            if result.returncode == 0:
                findings = json.loads(result.stdout) if result.stdout.strip() else []
            else:
                # Rule execution failed
                print(f"Rule execution error: {result.stderr}")
        
        finally:
            # Clean up script file
            if os.path.exists(script_path):
                os.unlink(script_path)
    
    except subprocess.TimeoutExpired:
        print(f"Rule execution timeout for rule: {rule.get('name')}")
    except json.JSONDecodeError:
        print(f"Invalid JSON output from rule: {rule.get('name')}")
    except Exception as e:
        print(f"Error executing Python rule: {e}")
    
    return findings

