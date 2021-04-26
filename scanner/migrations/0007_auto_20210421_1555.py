# Generated by Django 3.1.7 on 2021-04-21 15:55

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0006_auto_20210419_1748'),
    ]

    operations = [
        migrations.AlterField(
            model_name='vulnerability',
            name='description',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='vulnerability',
            name='extractor',
            field=models.CharField(max_length=500, null=True),
        ),
        migrations.AlterField(
            model_name='vulnerability',
            name='name',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='vulnerability',
            name='page',
            field=models.CharField(max_length=500, null=True),
        ),
        migrations.AlterField(
            model_name='vulnerability',
            name='protocol',
            field=models.CharField(max_length=200, null=True),
        ),
        migrations.AlterField(
            model_name='vulnerability',
            name='risk_level',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='vulnerability',
            name='template',
            field=models.CharField(max_length=500, null=True),
        ),
        migrations.AlterField(
            model_name='webhost',
            name='cname',
            field=models.CharField(max_length=500, null=True),
        ),
        migrations.AlterField(
            model_name='webhost',
            name='content_length',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='webhost',
            name='description',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='webhost',
            name='discovered_date',
            field=models.DateTimeField(default=django.utils.timezone.now, null=True),
        ),
        migrations.AlterField(
            model_name='webhost',
            name='http_status',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='webhost',
            name='port',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='webhost',
            name='screenshot_path',
            field=models.CharField(max_length=200, null=True),
        ),
        migrations.AlterField(
            model_name='webhost',
            name='server',
            field=models.CharField(max_length=500, null=True),
        ),
        migrations.AlterField(
            model_name='webhost',
            name='technologies',
            field=models.CharField(max_length=500, null=True),
        ),
        migrations.AlterField(
            model_name='webhost',
            name='url',
            field=models.CharField(max_length=200, null=True),
        ),
        migrations.AlterField(
            model_name='webhost',
            name='web_title',
            field=models.CharField(max_length=500, null=True),
        ),
    ]