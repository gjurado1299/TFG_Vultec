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


@login_required(login_url="/scanner/login/")
def index(request):
    context_dict = {}

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
def scan_configuration(request):
    context_dict = {}
    return render(request, 'scanner/scan-config.html', context=context_dict)


@login_required(login_url="/scanner/login/")
def show_all_scans(request):
    context_dict = {}

    if request.method == 'GET':
        scans = {}
        context_dict['msg'] = 'Total scans registered:'

        for s in list(Scan.objects.all()):
            target = Domain.objects.filter(scan=s, start_domain=True).first()
            scans[target] = s

        context_dict['scans'] = scans

    return render(request, 'scanner/scans.html', context=context_dict)


@login_required(login_url="/scanner/login/")
def add_scan(request, scan_id=None):
    context_dict = {}
    if request.method == 'POST':
        org_name = request.POST.get('org_name')
        target = request.POST.get('scan_target')
        config_id = request.POST.get('config_id')
        scan_id = request.POST.get('scan_id')

        if org_name and target and config_id:
            conf = Configuration.objects.filter(id=config_id).first()

            if scan_id:
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
    else:
        if scan_id:
            scan = Scan.objects.filter(id=scan_id).first()
            context_dict['scan'] = scan
            dom = Domain.objects.filter(scan=scan).first()
            context_dict['target'] = dom.name

    context_dict['chosen_config'] = Configuration.objects.all().filter(name="Subdomain discovery").first()
    return render(request, 'scanner/add-scan.html', context=context_dict)


@login_required(login_url="/scanner/login/")
def delete_scan(request, scan_id=None):

    if scan_id:
        Scan.objects.filter(id=scan_id).delete()
    
    return redirect("/scanner/scans/")


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

