# Generated migration for multi-tenancy

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('core', '0001_initial'),
    ]

    operations = [
        # Create Organization model
        migrations.CreateModel(
            name='Organization',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('domain', models.CharField(blank=True, max_length=255, null=True, unique=True)),
                ('poc_email', models.EmailField(max_length=254, verbose_name='Point of Contact Email')),
                ('status', models.CharField(choices=[('Active', 'Active'), ('Suspended', 'Suspended'), ('Inactive', 'Inactive')], default='Active', max_length=20)),
                ('settings', models.JSONField(blank=True, default=dict, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'ordering': ['name'],
            },
        ),
        # Create UserProfile model
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('role', models.CharField(choices=[('super_admin', 'Super Admin'), ('org_admin', 'Organization Admin'), ('org_user', 'Organization User'), ('org_viewer', 'Organization Viewer')], default='org_user', max_length=20)),
                ('phone', models.CharField(blank=True, max_length=20, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('organization', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='users', to='core.organization')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='userprofile', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['user__username'],
            },
        ),
        # Add organization to Rule (nullable for platform rules)
        migrations.AddField(
            model_name='rule',
            name='organization',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='rules', to='core.organization'),
        ),
        # Add organization and created_by to Audit (nullable for migration)
        migrations.AddField(
            model_name='audit',
            name='organization',
            field=models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.CASCADE, related_name='audits', to='core.organization'),
        ),
        migrations.AddField(
            model_name='audit',
            name='created_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='created_audits', to=settings.AUTH_USER_MODEL),
        ),
        # Create UserInvitation model
        migrations.CreateModel(
            name='UserInvitation',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(max_length=254)),
                ('role', models.CharField(choices=[('super_admin', 'Super Admin'), ('org_admin', 'Organization Admin'), ('org_user', 'Organization User'), ('org_viewer', 'Organization Viewer')], default='org_user', max_length=20)),
                ('token', models.CharField(max_length=64, unique=True)),
                ('expires_at', models.DateTimeField()),
                ('accepted_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('invited_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sent_invitations', to=settings.AUTH_USER_MODEL)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='invitations', to='core.organization')),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        # Create AuditLog model
        migrations.CreateModel(
            name='AuditLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('action_type', models.CharField(choices=[('create', 'Create'), ('update', 'Update'), ('delete', 'Delete'), ('login', 'Login'), ('logout', 'Logout'), ('invite', 'Invite User'), ('accept_invite', 'Accept Invitation')], max_length=20)),
                ('resource_type', models.CharField(choices=[('organization', 'Organization'), ('user', 'User'), ('audit', 'Audit'), ('rule', 'Rule'), ('finding', 'Finding'), ('asset', 'Asset')], max_length=20)),
                ('resource_id', models.IntegerField(blank=True, null=True)),
                ('description', models.TextField()),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('organization', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='audit_logs', to='core.organization')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='audit_logs', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        # Data migration: Delete all existing data (fresh start)
        # Delete findings first (they reference audits)
        migrations.RunPython(
            code=lambda apps, schema_editor: apps.get_model('core', 'Finding').objects.all().delete(),
            reverse_code=migrations.RunPython.noop,
        ),
        # Then delete audits
        migrations.RunPython(
            code=lambda apps, schema_editor: apps.get_model('core', 'Audit').objects.all().delete(),
            reverse_code=migrations.RunPython.noop,
        ),
    ]
