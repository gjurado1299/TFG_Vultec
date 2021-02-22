from django.contrib import admin
from scanner.models import Scan, Configuration, Domain, WebHost, Vulnerability


class ScanAdmin(admin.ModelAdmin):
    list_display = ('id', 'organization_name', 'scan_status',
                    'configuration', 'last_scan_date')

class ConfigurationAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'is_active', 'port_scan',
                    'subdomain_discovery', 'vulnerability_scan')

class DomainAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'scan', 'ip_address',
                    'open_ports', 'start_domain')

class WebHostAdmin(admin.ModelAdmin):
    list_display = ('id', 'domain', 'http_status', 'url',
                    'description', 'port', 'web_title', 'content_length', 'discovered_date')

class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('id', 'host', 'description', 'risk_level',
                    'vuln_type')


# Register your models here
admin.site.register(Scan, ScanAdmin)
admin.site.register(Configuration, ConfigurationAdmin)
admin.site.register(Domain, DomainAdmin)
admin.site.register(WebHost, WebHostAdmin)
admin.site.register(Vulnerability, VulnerabilityAdmin)
