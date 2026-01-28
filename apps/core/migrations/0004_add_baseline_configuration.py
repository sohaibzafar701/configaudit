# Generated manually for BaselineConfiguration model

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0003_alter_audit_organization_passwordresettoken_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='BaselineConfiguration',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('description', models.TextField(blank=True, null=True)),
                ('vendor', models.CharField(blank=True, max_length=100, null=True)),
                ('device_type', models.CharField(blank=True, max_length=100, null=True)),
                ('compliance_frameworks', models.CharField(blank=True, max_length=500, null=True)),
                ('rule_ids', models.JSONField(blank=True, default=list)),
                ('template_config', models.TextField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('organization', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='baselines', to='core.organization')),
            ],
            options={
                'verbose_name': 'Baseline Configuration',
                'verbose_name_plural': 'Baseline Configurations',
                'ordering': ['name'],
            },
        ),
    ]
