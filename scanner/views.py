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
from scanner.models import Scan, Configuration, Domain, WebHost, Vulnerability, RiskLevel, VulnerabilityType, ScanStatus
from django.utils import timezone

from django.conf import settings as conf_settings
import subprocess
import threading


def runScripts(scan, target):
    if scan.configuration.subdomain_discovery:
        subprocess.call([str(conf_settings.SRIPTS_DIR)+'/find_subdomains.sh', '-d', target, '-all']) 
        with open(conf_settings.RESULTS_DIR+'/'+target+'/subdomains.txt', 'r') as fin:
            lines = fin.read().splitlines()
            for line in lines:
                Domain.objects.create(name=line, scan=scan, ip_address='', open_ports='')
    
    if scan.configuration.web_discovery:
        subprocess.call([str(conf_settings.SRIPTS_DIR)+'/web_alives.sh', target ]) 
        with open(conf_settings.RESULTS_DIR+'/'+target+'/webalives.txt', 'r') as fin:
            lines = fin.read().splitlines()
            for line in lines:
                params = line.split(' [')
                url = params[0]
                _, domain_name, port = url.split(':')
                domain = Domain.objects.filter(name=domain_name[2:]).first()
                if domain:
                    domain.ip_address = params[5][:-1]
                    domain.save()
                    WebHost.objects.create(domain=domain, http_status=int(params[1][:-1]), url=url, port=port, web_title=params[3][:-1], server=params[4][:-1], cname=params[6][:-1],content_length=int(params[2][:-1]))

    scan.scan_stats = ScanStatus.FINISHED
    scan.last_scan_date = timezone.now()
    scan.save()


@login_required(login_url="/scanner/login/")
def index(request):
    context_dict = {}
    context_dict['organizations'] = Scan.objects.all()

    context_dict['total_scans'] = Scan.objects.count()
    context_dict['total_targets'] = Domain.objects.filter(start_domain=True).count()
    context_dict['discovered_subdomains'] = Domain.objects.filter(start_domain=False).count()
    context_dict['discovered_hosts'] = WebHost.objects.count()
    context_dict['vulnerabilities'] = list(Vulnerability.objects.all().order_by('risk_level')[0:5])
    context_dict['latest_scan'] = Scan.objects.all().exclude(last_scan_date=None).order_by('-last_scan_date').first()
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
        t = threading.Thread(name='runScripts', target=runScripts, args=(scan, target))
        t.start()
    
    return redirect("/scanner/")


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
        
        context_dict['chosen_config'] = Configuration.objects.all().filter(name="Subdomain discovery").first()

    else:
        if scan_id != None and scan_id != 0 and scan_id != "":
            scan = Scan.objects.filter(id=scan_id).first()
            context_dict['scan'] = scan
            dom = Domain.objects.filter(scan=scan).first()
            context_dict['target'] = dom.name
            context_dict['chosen_config'] = scan.configuration
        else:
            context_dict['chosen_config'] = Configuration.objects.all().filter(name="Subdomain discovery").first()
        
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

        if(conf_id):
            config = Configuration.objects.get(id=conf_id)
            config.web_discovery = (web_discovery == 'on')
            config.port_scan = (port_scan == 'on')
            config.subdomain_discovery = (subdomain_discovery == 'on')
            config.vulnerability_scan = (vulnerability_scan == 'on')
            config.save()
        else:
            conf_name = request.POST.get('conf_name')
            c = Configuration.objects.create(web_discovery=(web_discovery == 'on'), 
                                            port_scan=(port_scan == 'on'), 
                                            subdomain_discovery=(subdomain_discovery == 'on'), 
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
def scan_info(request, scan_id=None):

    context_dict = {}
    context_dict['organizations'] = Scan.objects.all()

    if scan_id:
        scan = Scan.objects.filter(id=scan_id).first()
        context_dict['scan'] = scan
        context_dict['targets'] = list(Domain.objects.filter(scan=scan))
        context_dict['webs'] = []

        for target in context_dict['targets']:
            context_dict['webs'].extend(list(WebHost.objects.filter(domain=target)))
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
        '''print(request.path)
        load_template = request.path.split('/')[-1]
        context['segment'] = load_template
        
        html_template = loader.get_template(load_template)
        return HttpResponse(html_template.render(context, request))'''
        return render(request, request.path[1:])
        
    except template.TemplateDoesNotExist:

        html_template = loader.get_template('scanner/pages/page-404.html')
        return HttpResponse(html_template.render(context, request))

    except:
    
        html_template = loader.get_template('scanner/pages/page-500.html')
        return HttpResponse(html_template.render(context, request))

