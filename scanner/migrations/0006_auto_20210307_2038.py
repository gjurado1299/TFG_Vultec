# Generated by Django 3.1.5 on 2021-03-07 20:38

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0005_auto_20210222_2004'),
    ]

    operations = [
        migrations.RenameField(
            model_name='configuration',
            old_name='is_active',
            new_name='web_discovery',
        ),
    ]