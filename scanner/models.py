from django.db import models
from enum import Enum
from django.utils import timezone

from scanner.managers import VulnerabilityManager

class ScanStatus(Enum):
    NEVER_SCANNED = 'Never scanned'
    SCANNING = 'Scanning'
    ERROR = 'Error'
    FINISHED = 'Finished scan'


class Configuration(models.Model):
    name = models.CharField(max_length=50, default="New configuration")
    web_discovery = models.BooleanField(default=False)
    port_scan = models.BooleanField(default=False)
    subdomain_discovery = models.BooleanField(default=True)
    tool_amass = models.BooleanField(default=False)
    tool_subfinder = models.BooleanField(default=False)
    tool_assetfinder = models.BooleanField(default=False)
    tool_bruteforce = models.BooleanField(default=False)
    vulnerability_scan = models.BooleanField(default=False)
    default = models.BooleanField(default=False)

    # Add more options

    def __str__(self):
        return self.name


class Scan(models.Model):
    organization_name = models.CharField(max_length=100, blank=True) 
    scan_status = models.CharField(max_length=100, choices=[(tag, tag.value) for tag in ScanStatus], default=ScanStatus.NEVER_SCANNED)
    configuration = models.ForeignKey(Configuration, on_delete=models.CASCADE)
    last_scan_date = models.DateTimeField(null=True)
    last_error_log = models.CharField(max_length=500, default="")

    def __str__(self):
        return self.organization_name


class Domain(models.Model):
    name = models.CharField(max_length=100, null=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, db_index=True)
    ip_address = models.CharField(max_length=100, default="")
    open_ports = models.CharField(max_length=500, default="")
    start_domain = models.BooleanField(default=False)

    def __str__(self):
        return self.name


class WebHost(models.Model):
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, db_index=True, related_name="hosts")
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, db_index=True, null=True)
    http_status = models.IntegerField(null=True)
    url = models.CharField(max_length=200, null=True)
    description = models.TextField(blank=True, null=True)
    port = models.IntegerField(null=True)
    web_title = models.CharField(max_length=500, null=True)
    cname = models.CharField(max_length=500, null=True)
    server = models.CharField(max_length=500, null=True)
    content_length = models.IntegerField(null=True)
    screenshot_path = models.CharField(max_length=200, null=True)
    technologies = models.CharField(max_length=500, null=True)
    discovered_date = models.DateTimeField(default=timezone.now, null=True)

    def __str__(self):
        return self.url


class Vulnerability(models.Model):
    host = models.ForeignKey(WebHost, on_delete=models.CASCADE, db_index=True, related_name="vulnerabilities")
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, db_index=True, null=True)
    name = models.CharField(max_length=100, null=True)
    page = models.CharField(max_length=1000, null=True)
    description = models.TextField(blank=True, null=True)
    risk_level = models.CharField(max_length=100, null=True)
    template = models.CharField(max_length=500, null=True)
    protocol = models.CharField(max_length=200, null=True)
    extractor = models.CharField(max_length=500, null=True)
    timestamp = models.DateTimeField(default=timezone.now)

    objects = VulnerabilityManager()
    
    def __str__(self):
        return "{}: {}".format(self.name, self.risk_level)

    class Meta:
        verbose_name_plural = 'Vulnerabilities'