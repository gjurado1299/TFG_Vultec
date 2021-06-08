# -*- encoding: utf-8 -*-

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.template import loader
from django import template
from django.contrib.auth.models import User
from django.forms.utils import ErrorList
from django.http import HttpResponse
from .forms import LoginForm
from scanner.models import Scan, Configuration, Domain, WebHost, Vulnerability, ScanStatus
from django.utils import timezone
from django.core import serializers
from django.forms.models import model_to_dict

from django.conf import settings as conf_settings
import subprocess
import threading
import json
import time


def chargeDomains(scan, target):
    with open(conf_settings.RESULTS_DIR+'/'+target+'/subdomains.txt', 'r') as fin:
        lines = fin.read().splitlines()
        for line in lines:
            Domain.objects.get_or_create(name=line, scan=scan)

    print("Finished charging domains")


def chargePorts(target):
    with open(conf_settings.RESULTS_DIR+'/'+target+'/ports_discovered.txt', 'r') as fin:
        for line in fin:
            data = {}
            data = json.loads(line)
            domain = Domain.objects.filter(name=data['host']).first()

            if domain:
                port = data.get('port','')
                if domain.open_ports == "":
                    domain.open_ports = port
                else:
                    if str(port) not in domain.open_ports and port != '':
                        domain.open_ports += ", {}".format(port)

                domain.save()
    print("Finished charging ports")


def chargeWebs(scan, target):
    with open(conf_settings.RESULTS_DIR+'/'+target+'/webalives.txt', 'r') as fin:
        with open(conf_settings.RESULTS_DIR+'/'+target+'/webalives_scan.txt', 'w') as fout:
            for line in fin:
                data = {}
                data = json.loads(line)
                
                url = data.get('url','')
                _, domain_name, port = url.split(':')
                domain = Domain.objects.filter(name=domain_name[2:]).first()
                if domain:
                    
                    domain.ip_address = data.get('host', '')
                    domain.save()
                    cname = ''
                    techs = ''

                    if 'cnames' in data:
                        cname = ', '.join(data['cnames'])

                    if 'technologies' in data:
                        techs = ', '.join(data['technologies'])

                    WebHost.objects.get_or_create(domain=domain, scan=scan, http_status=data.get('status-code', int()), url=url, port=port, web_title=data.get('title',''), server=data.get('webserver',''), 
                                                cname=cname, content_length=data.get('content-length', int()), technologies=techs)
                    fout.write(url+"\n")
    print("Finished charging webs")
    

def chargeVulnerabilities(scan, target):
    with open(conf_settings.RESULTS_DIR+'/'+target+'/nuclei_results_draft.txt', 'r') as f:
        i = 0
        for line in f:
            data = {}
            data = json.loads(line)
            extracted = ''
            host = WebHost.objects.filter(url=data.get('host','')).first()
            i += 1
            #if 'extracted_results' in data:
            #    extracted  = '|'.join(data['extracted_results'])
            if host:
                
                Vulnerability.objects.get_or_create(host=host, scan=scan, name=data['info']['name'], page=data['matched'].replace(data['host'], ''), description=data['info'].get('description',''), risk_level=data['info']['severity'], template=data['templateID'], protocol=data['type'], extractor=extracted)
    
    print("Finished charging vulnerabilities")


def get_vuln_count(request):
    data = ""
    severity_count = {}
    for v in list(Vulnerability.objects.all()):
        severity = v.risk_level
        if severity not in severity_count:
            severity_count[severity] = 0
        severity_count[severity] += 1
    

    data = "#".join(str(e) for e in list(severity_count.values())[1:])
    return HttpResponse(data, content_type="text/plain")


def runScripts(scan, target):
    try:
        scan.last_error_log = ""
        scan.current_thread = threading.get_ident()
        if scan.configuration.subdomain_discovery:
            flags = ""
            print("DISCOVERING SUBDOMAINS thread nº {}".format(scan.current_thread))
            if scan.configuration.tool_amass: flags += " -A"
            if scan.configuration.tool_assetfinder: flags += " -aF"
            if scan.configuration.tool_subfinder: flags += " -sF"
            if scan.configuration.tool_bruteforce: flags += " -BF"

            subprocess.call([str(conf_settings.SCRIPTS_DIR)+'/find_subdomains.sh', '-d', target, flags]) 
            chargeDomains(scan, target)

        if scan.configuration.port_scan:
            print("DISCOVERING PORTS thread nº {}".format(scan.current_thread))
            subprocess.call([str(conf_settings.SCRIPTS_DIR)+'/port_scan.sh', target])
            chargePorts(target)


        if scan.configuration.web_discovery:
            print("DISCOVERING WEBS thread nº {}".format(scan.current_thread))
            subprocess.call([str(conf_settings.SCRIPTS_DIR)+'/web_alives.sh', target ]) 
            chargeWebs(scan, target)
        
        if scan.configuration.vulnerability_scan:
            print("DISCOVERING VULNERABILITIES thread nº {}".format(scan.current_thread))
            subprocess.call([str(conf_settings.SCRIPTS_DIR)+'/vulnerabilities.sh', target ]) 
            chargeVulnerabilities(scan, target)

        scan.scan_status = ScanStatus.FINISHED.value

    except Exception as e:
        print("SCAN ERROR: {}".format(e.__traceback__s))
        scan.scan_status = ScanStatus.ERROR.value
        scan.last_error_log = str(e)
        
    finally:
        print("SCAN FINISHED")
        scan.current_thread = None
        scan.last_scan_date = timezone.now()
        scan.save()


def reload_any(request):
    scan_id = int(request.GET.get('scan_id', -1))
    target = request.GET.get('target', '')
    option = int(request.GET.get('option', -1))
    scan = Scan.objects.filter(id=scan_id).first()
    
    if option == 0:
        chargeDomains(scan, target)
    elif option == 1:
        chargePorts(target)
    elif option == 2:
        chargeWebs(scan, target)
    elif option == 3:
        chargeVulnerabilities(scan, target)

    scan.scan_status = ScanStatus.FINISHED.value
    if scan.last_scan_date is None:
        scan.last_scan_date = timezone.now()

    scan.save()
    return redirect("/scanner/scans/")


@login_required(login_url="/scanner/login/")
def index(request):
    context_dict = {}
    context_dict['organizations'] = Scan.objects.all()

    context_dict['total_scans'] = Scan.objects.count()
    context_dict['total_targets'] = Domain.objects.filter(start_domain=True).count()
    context_dict['discovered_subdomains'] = Domain.objects.filter(start_domain=False).count()
    context_dict['discovered_hosts'] = WebHost.objects.count()
    context_dict['vulnerabilities'] = list(Vulnerability.objects.preferred_order()[0:5])
    context_dict['latest_scan'] = Scan.objects.all().exclude(last_scan_date=None).order_by('-last_scan_date').first()
    context_dict['currently_scanning'] = Scan.objects.filter(scan_status=ScanStatus.SCANNING.value)
    context_dict['latest_subdomains'] = Domain.objects.filter(scan=context_dict['latest_scan'], start_domain=False).count()
    context_dict['latest_target'] = Domain.objects.filter(scan=context_dict['latest_scan'], start_domain=True).first()

    return render(request, 'scanner/index.html', context=context_dict)


@login_required(login_url="/scanner/login/")
def scan_configuration(request, select=-1):
    context_dict = {}
    context_dict['organizations'] = Scan.objects.all()
    if request.method == 'GET':
        context_dict['configurations'] = Configuration.objects.all()
        if select < 0:
            context_dict['select'] = False
            context_dict['scan'] = None
        else:
            context_dict['select'] = True
            context_dict['scan'] = Scan.objects.filter(id=select).first() if select != 0 else None
    else:
        selectedConf = request.POST.get('selectedConf')
        scan_id = request.POST.get('scan_id')
        if scan_id == "":
            scan_id = None
        if selectedConf and scan_id:
            return redirect('add_scan', scan_id=scan_id, chosen=str(selectedConf))
        elif selectedConf:
            return redirect('add_scan', scan_id=0, chosen=str(selectedConf))
        elif scan_id:
            return redirect('add_scan', scan_id=scan_id)
        else:
            return redirect('add_scan')

    return render(request, 'scanner/scan-config.html', context=context_dict)


@login_required(login_url="/scanner/login/")
def vulnerabilities(request):
    context_dict = {}
    context_dict['organizations'] = Scan.objects.all()
    return render(request, 'scanner/vulnerabilities.html', context=context_dict)


@login_required(login_url="/scanner/login/")
def show_all_scans(request):
    context_dict = {}
    context_dict['organizations'] = Scan.objects.all()

    if request.method == 'GET':
        scans = {}
        context_dict['msg'] = 'Total scans registered:'

        for s in list(Scan.objects.all()):
            target = Domain.objects.filter(scan=s, start_domain=True).first()
            scans[target] = s

        context_dict['scans'] = scans

    return render(request, 'scanner/scans.html', context=context_dict)


@login_required(login_url="/scanner/login/")
def run_scan(request, scan_id=None):

    if scan_id != None:
        scan = Scan.objects.filter(id=scan_id).first()
        scan.scan_status = ScanStatus.SCANNING.value
        scan.save()
        target = Domain.objects.filter(scan=scan, start_domain=True).first().name
        t = threading.Thread(name='runScripts', target=runScripts, args=(scan, target), daemon=True)
        t.start()
    
    return redirect("/scanner/scans/")


@login_required(login_url="/scanner/login/")
def add_scan(request, scan_id=None, chosen=None):
    context_dict = {}
    context_dict['organizations'] = Scan.objects.all()

    if request.method == 'POST':
        org_name = request.POST.get('org_name')
        target = request.POST.get('scan_target')
        config_id = request.POST.get('config_id')
        scan_id = request.POST.get('scan_id')

        if org_name and target and config_id:
            conf = Configuration.objects.filter(id=config_id).first()

            if scan_id != None and scan_id != 0 and scan_id != "":
                scan = Scan.objects.get(id=scan_id)
                dom = Domain.objects.get(scan=scan, start_domain=True)
                scan.organization_name = org_name
                scan.configuration = conf
                dom.name = target
                scan.save()
                dom.save()
            else:
                scan = Scan.objects.create(organization_name=org_name, scan_status=ScanStatus.NEVER_SCANNED.value, configuration=conf)
                Domain.objects.create(name=target, scan=scan, start_domain=True)
            
            return redirect("/scanner/scans/")
        
        context_dict['chosen_config'] = Configuration.objects.all().filter(name="Full scan").first()

    else:
        if scan_id != None and scan_id != 0 and scan_id != "":
            scan = Scan.objects.filter(id=scan_id).first()
            context_dict['scan'] = scan
            dom = Domain.objects.filter(scan=scan).first()
            context_dict['target'] = dom.name
            context_dict['chosen_config'] = scan.configuration
        else:
            context_dict['chosen_config'] = Configuration.objects.all().filter(name="Full scan").first()
        
        if chosen:
            context_dict['chosen_config'] = Configuration.objects.all().filter(id=int(chosen)).first()

    return render(request, 'scanner/add-scan.html', context=context_dict)


@login_required(login_url="/scanner/login/")
def add_config(request, conf_id=None):
    context_dict = {}
    context_dict['organizations'] = Scan.objects.all()

    if request.method == 'POST':
        web_discovery = request.POST.get('web_discovery')
        vulnerability_scan = request.POST.get('vulnerability_scan')
        port_scan = request.POST.get('port_scan')
        subdomain_discovery = request.POST.get('subdomain_discovery')
        tool_amass = request.POST.get('tool_amass')
        tool_subfinder = request.POST.get('tool_subfinder')
        tool_assetfinder = request.POST.get('tool_assetfinder')
        tool_bruteforce = request.POST.get('tool_bruteforce')

        if(conf_id):
            config = Configuration.objects.get(id=conf_id)
            config.web_discovery = (web_discovery == 'on')
            config.port_scan = (port_scan == 'on')
            config.subdomain_discovery = (subdomain_discovery == 'on')
            config.tool_amass = (tool_amass == 'on')
            config.tool_subfinder = (tool_subfinder == 'on')
            config.tool_assetfinder = (tool_assetfinder == 'on')
            config.tool_bruteforce = (tool_bruteforce == 'on')
            config.vulnerability_scan = (vulnerability_scan == 'on')
            config.save()
        else:
            conf_name = request.POST.get('conf_name')
            c = Configuration.objects.create(web_discovery=(web_discovery == 'on'), 
                                            port_scan=(port_scan == 'on'), 
                                            subdomain_discovery=(subdomain_discovery == 'on'), 
                                            tool_amass=(tool_amass == 'on'), 
                                            tool_subfinder=(tool_subfinder == 'on'), 
                                            tool_assetfinder=(tool_assetfinder == 'on'), 
                                            tool_bruteforce=(tool_bruteforce == 'on'), 
                                            vulnerability_scan=(vulnerability_scan == 'on'))
            if(conf_name != ""):
                c.name = conf_name
                c.save()
        
        return redirect("/scanner/config/")

    return render(request, 'scanner/add-conf.html', context=context_dict)


@login_required(login_url="/scanner/login/")
def delete_scan(request, scan_id=None):

    if scan_id:
        Scan.objects.filter(id=scan_id).delete()
    
    return redirect("/scanner/scans/")


@login_required(login_url="/scanner/login/")
def stop_scan(request, scan_id=None):

    if scan_id:
        scan = Scan.objects.filter(id=scan_id).first()
        if scan.current_thread != None:
            
            print("SCAN STOPPED")
            scan.current_thread = None
            scan.last_scan_date = timezone.now()
            scan.save()
    
    return redirect("/scanner/scans/")

def load_scan_targets(request):

    scan_id = int(request.GET.get('scan_id', -1))
    targets = []
    data = {}

    if scan_id != -1:
        scan = Scan.objects.filter(id=scan_id).first()
        targets = list(Domain.objects.filter(scan=scan).values_list('name', 'ip_address', 'open_ports'))
    
    data['data'] = [*map(list, targets)]
    return HttpResponse(json.dumps(data, default=str), content_type="application/json")


def load_scan_webs(request):

    scan_id = int(request.GET.get('scan_id', -1))
    webs = []
    data = {}
    if scan_id != -1:
        scan = Scan.objects.filter(id=scan_id).first()
        webs = list(WebHost.objects.filter(scan=scan).values_list('domain__name', 'port', 'http_status', 'web_title', 'content_length', 
                                                                  'server', 'cname', 'technologies', 'discovered_date'))
    
    data['data'] = [*map(list, webs)]
    return HttpResponse(json.dumps(data, default=str), content_type="application/json")



def load_scan_vulns(request):

    id = request.GET.get('scan_id', -1)
    scan_id = -1
    if id != "":
        scan_id = int(id)

    vulns = []
    data = {}
    if scan_id != -1:
        start = time.time()
        scan = Scan.objects.filter(id=scan_id).first()
        end = time.time()
        print("Time finding scan: {}".format(end-start))

        start = time.time()
        vulns = list(Vulnerability.objects.filter(scan=scan).values_list('host__url', 'name', 'page', 'description', 'risk_level', 
                                                                  'template', 'protocol', 'extractor', 'timestamp'))
        end = time.time()
        print("Time filtering vulnerabilities: {}".format(end-start))
    else:
        vulns = list(Vulnerability.objects.all().values_list('host__url', 'name', 'page', 'description', 'risk_level', 
                                                                'template', 'protocol', 'extractor', 'timestamp'))

    data['data'] = [*map(list, vulns)]
    return HttpResponse(json.dumps(data, default=str), content_type="application/json")


    
@login_required(login_url="/scanner/login/")
def scan_info(request, scan_id=None):

    context_dict = {}
    context_dict['organizations'] = Scan.objects.all()

    if scan_id:
        context_dict['scan_id'] = scan_id
        return render(request, 'scanner/scan-info.html', context=context_dict)

    return redirect("/scanner/")


@login_required(login_url="/scanner/login/")
def delete_config(request, conf_id=None):

    if conf_id:
        Configuration.objects.filter(id=conf_id).delete()
    
    return redirect("/scanner/config/")


def login_view(request):
    form = LoginForm(request.POST or None)
    msg = ""

    if request.method == "POST":
        if form.is_valid():
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password")
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect("/")
            else:    
                msg = 'Invalid credentials'    
        else:
            msg = 'Error validating the form'    

    return render(request, "scanner/login.html", {"form": form, "msg" : msg})


def register_user(request):
    authenticate(username='gonxo', password='tfg2021')
    return redirect("/scanner/login/")


@login_required(login_url="/scanner/login/")
def pages(request, html):

    context = {}
    # All resource paths end in .html.
    # Pick out the html file name from the url. And load that template.
    try:
        return render(request, request.path[1:])
        
    except template.TemplateDoesNotExist:

        html_template = loader.get_template('scanner/pages/page-404.html')
        return HttpResponse(html_template.render(context, request))

    except:
    
        html_template = loader.get_template('scanner/pages/page-500.html')
        return HttpResponse(html_template.render(context, request))

