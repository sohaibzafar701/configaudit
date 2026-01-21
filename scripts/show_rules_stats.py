#!/usr/bin/env python3
"""Show rules statistics"""

from models.rule import Rule

rules = Rule.get_all(enabled_only=False)
print(f'Total rules: {len(rules)}')

# Count by category
cats = {}
for r in rules:
    cat = r['category'] or 'Uncategorized'
    cats[cat] = cats.get(cat, 0) + 1

print('\nRules by category:')
for k, v in sorted(cats.items()):
    print(f'  {k}: {v}')

# Count by severity
sevs = {}
for r in rules:
    sev = r['severity'] or 'unknown'
    sevs[sev] = sevs.get(sev, 0) + 1

print('\nRules by severity:')
for k, v in sorted(sevs.items()):
    print(f'  {k}: {v}')

