"""
Django management command to create super admin user
"""
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from apps.core.models import UserProfile


class Command(BaseCommand):
    help = 'Create a super admin user'

    def add_arguments(self, parser):
        parser.add_argument('--username', type=str, help='Username for super admin')
        parser.add_argument('--email', type=str, help='Email for super admin')
        parser.add_argument('--password', type=str, help='Password for super admin')

    def handle(self, *args, **options):
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
        if User.objects.filter(username=username).exists():
            self.stdout.write(self.style.ERROR(f'User "{username}" already exists'))
            return
        
        if User.objects.filter(email=email).exists():
            self.stdout.write(self.style.ERROR(f'User with email "{email}" already exists'))
            return
        
        # Create user
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password
        )
        
        # Create profile with super admin role
        profile = UserProfile.objects.create(
            user=user,
            role=UserProfile.ROLE_SUPER_ADMIN,
            organization=None  # Super admin has no organization
        )
        
        self.stdout.write(self.style.SUCCESS(f'Super admin "{username}" created successfully'))
        self.stdout.write(f'  Email: {email}')
        self.stdout.write(f'  Role: Super Admin')
