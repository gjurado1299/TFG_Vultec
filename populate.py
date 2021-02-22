import django
import os
from datetime import date 
from datetime import timedelta 

os.environ.setdefault('DJANGO_SETTINGS_MODULE',
                      'Vultec.settings')

django.setup()

from scanner.models import Scan, Configuration, Domain, WebHost, Vulnerability, RiskLevel, VulnerabilityType, ScanStatus

config1, c = Configuration.objects.get_or_create(name="Subdomain discovery", default=True)
config2, c = Configuration.objects.get_or_create(name="Full scan", is_active=True, port_scan=True, vulnerability_scan=True, default=True)

scan1, s = Scan.objects.get_or_create(organization_name='UAM', scan_status=ScanStatus.NEVER_SCANNED.value, configuration=config1)
scan2, s = Scan.objects.get_or_create(organization_name='HackerOne', scan_status=ScanStatus.SCANNING.value, configuration=config2, last_scan_date=date.today())
scan3, s = Scan.objects.get_or_create(organization_name='Twitter', scan_status=ScanStatus.FINISHED.value, configuration=config2, last_scan_date=date.today() - timedelta(days = 1))

Domain.objects.get_or_create(name='uam.es', scan=scan1, ip_address='255.255.255.255', open_ports='443,80', start_domain=True)
domain2, d = Domain.objects.get_or_create(name='eps.uam.es', scan=scan1, ip_address='255.255.255.255', open_ports='443,80')
Domain.objects.get_or_create(name='hackerone.com', scan=scan2, ip_address='255.255.255.255', open_ports='443,80', start_domain=True)
Domain.objects.get_or_create(name='doc.hackerone.com', scan=scan2, ip_address='255.255.255.255', open_ports='443,80')
domain5, d = Domain.objects.get_or_create(name='mta-sts.hackerone.com', scan=scan2, ip_address='255.255.255.255', open_ports='443,80')
Domain.objects.get_or_create(name='twitter.com', scan=scan3, ip_address='255.255.255.255', open_ports='443,80', start_domain=True)


webh, w = WebHost.objects.get_or_create(domain=domain2, http_status=200, url='https://www.eps.uam.es/', port=443, web_title='Escuela Politecnica Superior', content_length=65871, screenshot_path='/images/screenshots/eps.png')
webh2, w = WebHost.objects.get_or_create(domain=domain5, http_status=404, url='http://www.mta-sts.hackerone.com/', port=80, web_title='Page not Found', content_length=9339, screenshot_path='/images/screenshots/notFound.png')

Vulnerability.objects.get_or_create(host=webh2, risk_level=RiskLevel.LOW.value, vuln_type=VulnerabilityType.XSS.value)
Vulnerability.objects.get_or_create(host=webh2, risk_level=RiskLevel.MODERATE.value, vuln_type=VulnerabilityType.SQLINJECTION.value)
Vulnerability.objects.get_or_create(host=webh, risk_level=RiskLevel.HIGH.value, vuln_type=VulnerabilityType.DNS.value)
Vulnerability.objects.get_or_create(host=webh, risk_level=RiskLevel.CRITICAL.value, vuln_type=VulnerabilityType.SQLINJECTION.value)
Vulnerability.objects.get_or_create(host=webh, risk_level=RiskLevel.MODERATE.value, vuln_type=VulnerabilityType.XSS.value)
Vulnerability.objects.get_or_create(host=webh2, risk_level=RiskLevel.CRITICAL.value, vuln_type=VulnerabilityType.DNS.value)