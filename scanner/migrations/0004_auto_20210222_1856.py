# Generated by Django 3.1.5 on 2021-02-22 18:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0003_configuration_default'),
    ]

    operations = [
        migrations.AlterField(
            model_name='domain',
            name='ip_address',
            field=models.CharField(default='', max_length=100),
        ),
        migrations.AlterField(
            model_name='domain',
            name='open_ports',
            field=models.CharField(default='', max_length=100),
        ),
    ]
