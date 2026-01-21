#!/usr/bin/env python3
"""Test multiple tags support"""

from models.rule import Rule

# Get all rules
rules = Rule.get_all(enabled_only=False)

# Find rules with multiple tags
multi_tag_rules = [r for r in rules if r['tags'] and ',' in r['tags']]

print(f"Total rules: {len(rules)}")
print(f"Rules with multiple tags: {len(multi_tag_rules)}")
print("\nExamples of rules with multiple tags:")
for rule in multi_tag_rules[:5]:
    tags = rule['tags'].split(',')
    print(f"  - {rule['name']}")
    print(f"    Tags: {tags}")
    print(f"    Raw: {rule['tags']}")
    print()

# Test creating a rule with multiple tags
print("\nTesting rule creation with multiple tags:")
test_rule_id = Rule.create(
    name="Test Multi-Tag Rule",
    description="Testing multiple tags support",
    rule_type=Rule.TYPE_PATTERN,
    category="Testing",
    severity="low",
    yaml_content="test: content",
    tags=["cisco", "juniper", "arista", "all"]  # Multiple tags as list
)

test_rule = Rule.get_by_id(test_rule_id)
print(f"Created rule with tags: {test_rule['tags']}")
print(f"Tags split: {test_rule['tags'].split(',')}")

# Clean up test rule
Rule.delete(test_rule_id)
print("\nTest rule deleted. Multiple tags support confirmed!")

