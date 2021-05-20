from django.urls import path
from django.conf.urls import url
from scanner import views
from django.contrib.auth.views import LogoutView

urlpatterns = [
    path('', views.index, name='scanner'),
    path('login/', views.login_view, name='login'),
    path('config/', views.scan_configuration, name='configuration'),
    path('config/<int:select>/', views.scan_configuration, name='configuration'),
    path('scans/', views.show_all_scans, name='scans'),
    path('vulnerabilities/', views.vulnerabilities, name='vulnerabilities'),
    path('run-scan/', views.run_scan, name='run_scan'),
    path('scan-info/<int:scan_id>/', views.scan_info, name='scan_info'),
    path('run-scan/<int:scan_id>/', views.run_scan, name='run_scan'),
    path('add-scan/', views.add_scan, name='add_scan'),
    path('add-scan/<int:scan_id>/', views.add_scan, name='add_scan'),
    path('add-scan/<int:scan_id>/<str:chosen>/', views.add_scan, name='add_scan'),
    path('add-scan/<str:chosen>/', views.add_scan, name='add_scan'),
    path('add-conf/', views.add_config, name='add_conf'),
    path('add-conf/<int:conf_id>/', views.add_config, name='add_conf'),
    path('delete-scan/<int:scan_id>/', views.delete_scan, name='delete_scan'),
    path('delete-config/<int:conf_id>/', views.delete_config, name='delete_config'),
    path('register/', views.register_user, name="register"),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('pages/<str:html>/', views.pages, name='pages'),
    url(r'^reload_any/$', views.reload_any, name='reload_any'),
    url(r'^load_scan_targets/$', views.load_scan_targets, name='load_scan_targets'),
    url(r'^load_scan_webs/$', views.load_scan_webs, name='load_scan_webs'),
    url(r'^load_scan_vulns/$', views.load_scan_vulns, name='load_scan_vulns'),
    url(r'^get_vuln_count/$', views.get_vuln_count, name='get_vuln_count')
]