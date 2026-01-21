"""
Django management command to create super admin user
"""
from django.core.management.base import BaseCommand
from django.core.management import call_command
from django.db import connection
from django.contrib.auth.models import User
from apps.core.models import UserProfile


class Command(BaseCommand):
    help = 'Create a super admin user'

    def add_arguments(self, parser):
        parser.add_argument('--username', type=str, help='Username for super admin')
        parser.add_argument('--email', type=str, help='Email for super admin')
        parser.add_argument('--password', type=str, help='Password for super admin')
        parser.add_argument(
            '--run-migrations',
            action='store_true',
            help='Automatically run migrations if database is not ready',
        )

    def check_database_ready(self):
        """Check if database tables exist by checking for auth_user table"""
        try:
            with connection.cursor() as cursor:
                # Check if auth_user table exists
                cursor.execute("""
                    SELECT name FROM sqlite_master 
                    WHERE type='table' AND name='auth_user'
                """)
                return cursor.fetchone() is not None
        except Exception:
            return False

    def handle(self, *args, **options):
        # Check if database is ready
        if not self.check_database_ready():
            self.stdout.write(
                self.style.ERROR(
                    'Database tables do not exist. Please run migrations first:\n'
                    '  python manage.py migrate\n\n'
                    'Or use --run-migrations to automatically run migrations.'
                )
            )
            if options.get('run_migrations'):
                self.stdout.write('Running migrations...')
                try:
                    call_command('migrate', verbosity=0)
                    self.stdout.write(self.style.SUCCESS('Migrations completed successfully.'))
                except Exception as e:
                    self.stdout.write(
                        self.style.ERROR(f'Error running migrations: {str(e)}')
                    )
                    return
            else:
                return
        
        username = options.get('username')
        email = options.get('email')
        password = options.get('password')
        
        if not username:
            username = input('Enter username: ')
        if not email:
            email = input('Enter email: ')
        if not password:
            import getpass
            password = getpass.getpass('Enter password: ')
        
        # Check if user already exists
        try:
            if User.objects.filter(username=username).exists():
                self.stdout.write(self.style.ERROR(f'User "{username}" already exists'))
                return
            
            if User.objects.filter(email=email).exists():
                self.stdout.write(self.style.ERROR(f'User with email "{email}" already exists'))
                return
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(
                    f'Error checking existing users: {str(e)}\n'
                    'This might indicate database issues. Please run migrations:\n'
                    '  python manage.py migrate'
                )
            )
            return
        
        # Create user
        try:
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error creating user: {str(e)}')
            )
            return
        
        # Create profile with super admin role
        try:
            profile = UserProfile.objects.create(
                user=user,
                role=UserProfile.ROLE_SUPER_ADMIN,
                organization=None  # Super admin has no organization
            )
        except Exception as e:
            # If profile creation fails, delete the user to avoid orphaned records
            user.delete()
            self.stdout.write(
                self.style.ERROR(
                    f'Error creating user profile: {str(e)}\n'
                    'User was not created. Please ensure all migrations are applied:\n'
                    '  python manage.py migrate'
                )
            )
            return
        
        self.stdout.write(self.style.SUCCESS(f'Super admin "{username}" created successfully'))
        self.stdout.write(f'  Email: {email}')
        self.stdout.write(f'  Role: Super Admin')
