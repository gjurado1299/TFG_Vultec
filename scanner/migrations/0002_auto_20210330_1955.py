# Generated by Django 3.1.7 on 2021-03-30 19:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='vulnerability',
            name='vuln_type',
        ),
        migrations.AddField(
            model_name='vulnerability',
            name='name',
            field=models.CharField(default='', max_length=100),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='vulnerability',
            name='page',
            field=models.CharField(default='', max_length=500),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='vulnerability',
            name='timestamp',
            field=models.CharField(default='', max_length=100),
            preserve_default=False,
        ),
    ]