"""
Django management command to load initial rules into the database
"""
from django.core.management.base import BaseCommand
from apps.core.models import Rule


class Command(BaseCommand):
    help = 'Load initial sample rules into the database'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force reload even if rules already exist',
        )

    def handle(self, *args, **options):
        force = options['force']
        
        # Check if rules already exist
        existing_count = Rule.objects.count()
        if existing_count > 0 and not force:
            self.stdout.write(
                self.style.WARNING(
                    f'Database already contains {existing_count} rules. '
                    'Use --force to reload sample rules.'
                )
            )
            return
        
        if force and existing_count > 0:
            self.stdout.write('Removing existing rules...')
            Rule.objects.all().delete()
        
        # Add sample rules
        self.stdout.write('Adding sample rules...')
        
        # Sample pattern rule 1
        Rule.objects.create(
            name="Default Password Check",
            description="Check for default passwords in configuration",
            rule_type=Rule.TYPE_PATTERN,
            category="Authentication",
            severity="high",
            yaml_content="""name: Default Password Check
type: pattern
pattern: 'password\\s+\\d+'
severity: high
message: "Default password detected"
""",
            tags="authentication,security,password",
            enabled=True
        )
        
        # Sample pattern rule 2
        Rule.objects.create(
            name="SSH Enabled Check",
            description="Check if SSH is enabled",
            rule_type=Rule.TYPE_PATTERN,
            category="Encryption",
            severity="medium",
            yaml_content="""name: SSH Enabled Check
type: pattern
pattern: 'ip\\s+ssh'
severity: medium
message: "SSH is enabled"
""",
            tags="encryption,ssh,remote-access",
            enabled=True
        )
        
        # Sample pattern rule 3
        Rule.objects.create(
            name="Access List Check",
            description="Check if access lists are configured",
            rule_type=Rule.TYPE_PATTERN,
            category="Access Control",
            severity="low",
            yaml_content="""name: Access List Check
type: pattern
pattern: 'ip\\s+access-list'
severity: low
message: "Access list found"
""",
            tags="access-control,acl,security",
            enabled=True
        )
        
        # Sample pattern rule 4 - Telnet disabled
        Rule.objects.create(
            name="Telnet Disabled Check",
            description="Check if Telnet is disabled (SSH should be used instead)",
            rule_type=Rule.TYPE_PATTERN,
            category="Encryption",
            severity="high",
            yaml_content="""name: Telnet Disabled Check
type: pattern
pattern: 'line\\s+vty.*\\n.*transport\\s+input\\s+telnet'
severity: high
message: "Telnet is enabled - should use SSH instead"
""",
            tags="encryption,security,telnet",
            enabled=True
        )
        
        # Sample pattern rule 5 - SNMP community strings
        Rule.objects.create(
            name="SNMP Community String Check",
            description="Check for weak SNMP community strings",
            rule_type=Rule.TYPE_PATTERN,
            category="Security",
            severity="medium",
            yaml_content="""name: SNMP Community String Check
type: pattern
pattern: 'snmp-server\\s+community\\s+(public|private)'
severity: medium
message: "Weak SNMP community string detected"
""",
            tags="security,snmp,monitoring",
            enabled=True
        )
        
        total = Rule.objects.count()
        self.stdout.write(
            self.style.SUCCESS(
                f'Successfully loaded {total} sample rules into the database!'
            )
        )
