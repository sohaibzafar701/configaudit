"""
Django management command to import rules from the original populate_rules.py script
"""
import sys
from pathlib import Path
from django.core.management.base import BaseCommand
from apps.core.models import Rule


class Command(BaseCommand):
    help = 'Import all rules from scripts/populate_rules.py into Django database'

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
        
        # Import the rule definitions from the original script
        # Path calculation: __file__ is in apps/core/management/commands/
        # Go up 5 levels: commands -> management -> core -> apps -> project_root
        # __file__ = apps/core/management/commands/import_rules.py
        # .parent = apps/core/management/commands/
        # .parent.parent = apps/core/management/
        # .parent.parent.parent = apps/core/
        # .parent.parent.parent.parent = apps/
        # .parent.parent.parent.parent.parent = project_root
        project_root = Path(__file__).parent.parent.parent.parent.parent
        scripts_path = project_root / 'scripts' / 'populate_rules.py'
        
        if not scripts_path.exists():
            self.stdout.write(
                self.style.ERROR(f'Could not find {scripts_path}')
            )
            return
        
        # Add project root to path to import the script
        sys.path.insert(0, str(project_root))
        
        try:
            # We need to mock the Rule model BEFORE importing the script
            # Create a mock Rule class that the script can use
            class MockRule:
                TYPE_PATTERN = "pattern"
                TYPE_PYTHON = "python"
                TYPE_HYBRID = "hybrid"
                
                @staticmethod
                def get_all(enabled_only=False):
                    # Return existing rules from Django
                    return [{'name': r.name} for r in Rule.objects.all()]
            
            # Temporarily replace models.rule in sys.modules BEFORE import
            import types
            mock_models = types.ModuleType('models')
            mock_models.rule = types.ModuleType('models.rule')
            mock_models.rule.Rule = MockRule
            
            # Store original if it exists
            original_models = sys.modules.get('models')
            original_models_rule = sys.modules.get('models.rule')
            
            # Set up mock modules BEFORE loading
            sys.modules['models'] = mock_models
            sys.modules['models.rule'] = mock_models.rule
            
            try:
                # Now import the populate_rules module (it will use our mock)
                import importlib.util
                spec = importlib.util.spec_from_file_location("populate_rules", scripts_path)
                populate_rules = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(populate_rules)
            finally:
                # Restore original modules
                if original_models:
                    sys.modules['models'] = original_models
                else:
                    if 'models' in sys.modules:
                        del sys.modules['models']
                
                if original_models_rule:
                    sys.modules['models.rule'] = original_models_rule
                else:
                    if 'models.rule' in sys.modules:
                        del sys.modules['models.rule']
            
            # Get all rule definitions
            all_rules = populate_rules.get_all_rules()
            
            self.stdout.write(f'Found {len(all_rules)} rules to import...')
            
            created_count = 0
            skipped_count = 0
            error_count = 0
            
            for i, rule_data in enumerate(all_rules, 1):
                name = rule_data.get('name', 'Unnamed Rule')
                
                # Check if rule exists
                if skip_existing and Rule.objects.filter(name=name).exists():
                    skipped_count += 1
                    if i % 50 == 0:
                        self.stdout.write(f'Progress: {i}/{len(all_rules)} (skipped: {skipped_count})')
                    continue
                
                try:
                    # Convert tags list to string
                    tags = rule_data.get('tags', [])
                    if isinstance(tags, list):
                        tags_str = ','.join(str(t) for t in tags)
                    else:
                        tags_str = str(tags) if tags else ''
                    
                    # Convert compliance_frameworks list to string
                    compliance_frameworks = rule_data.get('compliance_frameworks', '')
                    if isinstance(compliance_frameworks, list):
                        compliance_frameworks_str = ','.join(str(f) for f in compliance_frameworks)
                    else:
                        compliance_frameworks_str = str(compliance_frameworks) if compliance_frameworks else ''
                    
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
                        compliance_frameworks=compliance_frameworks_str,
                        framework_mappings=rule_data.get('framework_mappings'),
                        risk_weight=rule_data.get('risk_weight', 1.0),
                        enabled=True
                    )
                    created_count += 1
                    
                    if i % 50 == 0:
                        self.stdout.write(f'Progress: {i}/{len(all_rules)} (created: {created_count}, skipped: {skipped_count})')
                        
                except Exception as e:
                    error_count += 1
                    self.stdout.write(
                        self.style.ERROR(f'Error creating rule "{name}": {str(e)}')
                    )
            
            # Summary
            self.stdout.write('')
            self.stdout.write(self.style.SUCCESS('=' * 60))
            self.stdout.write(self.style.SUCCESS('Import Summary:'))
            self.stdout.write(self.style.SUCCESS(f'  Total rules processed: {len(all_rules)}'))
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
                self.style.ERROR(f'Error importing rules: {str(e)}')
            )
            import traceback
            self.stdout.write(traceback.format_exc())
