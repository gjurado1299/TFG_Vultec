from django.db import models
from enum import Enum
from django.utils import timezone

class RiskLevel(Enum):
    LOW = 'Low'
    MODERATE = 'Moderate'
    HIGH = 'High'
    CRITICAL = 'Critical'



class VulnerabilityType(Enum):
    DEFAULT = ''
    XSS = 'Cross site scripting'
    SQLINJECTION = 'SQL Injection'
    DNS = 'Denial of Service'

    def __str__(self):
        return str(self.value)


class ScanStatus(Enum):
    NEVER_SCANNED = 'Never scanned'
    SCANNING = 'Scanning'
    FINISHED = 'Finished scan'


class Configuration(models.Model):
    name = models.CharField(max_length=50, default="New configuration")
    web_discovery = models.BooleanField(default=False)
    port_scan = models.BooleanField(default=False)
    subdomain_discovery = models.BooleanField(default=True)
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

    def __str__(self):
        return self.organization_name


class Domain(models.Model):
    name = models.CharField(max_length=100, null=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE)
    ip_address = models.CharField(max_length=100, default="")
    open_ports = models.CharField(max_length=100, default="")
    start_domain = models.BooleanField(default=False)

    def __str__(self):
        return self.name


class WebHost(models.Model):
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
    http_status = models.IntegerField()
    url = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    port = models.IntegerField()
    web_title = models.CharField(max_length=500)
    cname = models.CharField(max_length=500)
    server = models.CharField(max_length=500)
    content_length = models.IntegerField()
    screenshot_path = models.CharField(max_length=200)
    discovered_date = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.url


class Vulnerability(models.Model):
    host = models.ForeignKey(WebHost, on_delete=models.CASCADE)
    description = models.TextField(blank=True)
    risk_level = models.CharField(max_length=100, choices=[(tag, tag.value) for tag in RiskLevel], default=RiskLevel.LOW)
    vuln_type = models.CharField(max_length=100, choices=[(tag, tag.value) for tag in VulnerabilityType], default=VulnerabilityType.DEFAULT)
    
    def __str__(self):
        return "{}: {}".format(self.vuln_type, self.risk_level)

    class Meta:
        verbose_name_plural = 'Vulnerabilities'