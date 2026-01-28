"""
Django management command to update platform baseline rule_ids
"""
from django.core.management.base import BaseCommand
from django.db.models import Q
from apps.core.models import BaselineConfiguration, Rule


class Command(BaseCommand):
    help = 'Update all platform baseline rule_ids based on current platform rules'

    def add_arguments(self, parser):
        parser.add_argument(
            '--baseline',
            type=str,
            help='Update only a specific baseline by name',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be updated without making changes',
        )

    def handle(self, *args, **options):
        baseline_name = options.get('baseline')
        dry_run = options.get('dry_run', False)
        
        if dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN MODE - No changes will be made'))
        
        # Get platform baselines
        if baseline_name:
            baselines = BaselineConfiguration.objects.filter(
                organization__isnull=True,
                name=baseline_name
            )
            if not baselines.exists():
                self.stdout.write(self.style.ERROR(f'Baseline "{baseline_name}" not found'))
                return
        else:
            baselines = BaselineConfiguration.objects.filter(organization__isnull=True)
        
        updated_count = 0
        
        for baseline in baselines:
            try:
                rule_ids = []
                
                # Get rules by vendor if baseline has vendor
                if baseline.vendor:
                    vendor_rules = Rule.objects.filter(
                        enabled=True,
                        organization__isnull=True,
                        tags__icontains=baseline.vendor.lower()
                    )
                    rule_ids.extend(vendor_rules.values_list('id', flat=True))
                
                # Get rules by compliance frameworks
                if baseline.compliance_frameworks:
                    baseline_frameworks = baseline.get_frameworks_list()
                    for framework in baseline_frameworks:
                        framework_rules = Rule.objects.filter(
                            enabled=True,
                            organization__isnull=True,
                            compliance_frameworks__icontains=framework
                        )
                        rule_ids.extend(framework_rules.values_list('id', flat=True))
                
                # Remove duplicates and convert to list
                rule_ids = list(set(rule_ids))
                old_count = len(baseline.rule_ids) if baseline.rule_ids else 0
                new_count = len(rule_ids)
                
                if set(baseline.rule_ids or []) != set(rule_ids):
                    if dry_run:
                        self.stdout.write(
                            self.style.WARNING(
                                f'Would update "{baseline.name}": {old_count} -> {new_count} rules'
                            )
                        )
                    else:
                        baseline.rule_ids = rule_ids
                        baseline.save(update_fields=['rule_ids'])
                        self.stdout.write(
                            self.style.SUCCESS(
                                f'Updated "{baseline.name}": {old_count} -> {new_count} rules'
                            )
                        )
                        updated_count += 1
                else:
                    self.stdout.write(
                        f'No changes needed for "{baseline.name}" ({new_count} rules)'
                    )
                    
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'Error updating baseline "{baseline.name}": {str(e)}')
                )
        
        if not dry_run:
            self.stdout.write(
                self.style.SUCCESS(f'\nSuccessfully updated {updated_count} baseline(s)')
            )
        else:
            self.stdout.write(
                self.style.WARNING(f'\nWould update {updated_count} baseline(s)')
            )
