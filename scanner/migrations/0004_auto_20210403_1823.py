# Generated by Django 3.1.7 on 2021-04-03 18:23

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0003_auto_20210401_1109'),
    ]

    operations = [
        migrations.AlterField(
            model_name='vulnerability',
            name='timestamp',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
    ]
