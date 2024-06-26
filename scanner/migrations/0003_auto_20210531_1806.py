# Generated by Django 3.1.7 on 2021-05-31 18:06

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0002_auto_20210507_1250'),
    ]

    operations = [
        migrations.AddField(
            model_name='configuration',
            name='tool_amass',
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name='configuration',
            name='tool_assetfinder',
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name='configuration',
            name='tool_bruteforce',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='configuration',
            name='tool_subfinder',
            field=models.BooleanField(default=True),
        ),
    ]
