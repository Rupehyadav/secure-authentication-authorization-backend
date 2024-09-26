# Generated by Django 5.1.1 on 2024-09-26 10:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='is_2fa_enabled',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='customuser',
            name='two_factor_code',
            field=models.CharField(blank=True, max_length=6, null=True),
        ),
        migrations.AddField(
            model_name='customuser',
            name='two_factor_code_expires',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
