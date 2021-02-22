from django.urls import path
from scanner import views
from django.contrib.auth.views import LogoutView

urlpatterns = [
    path('', views.index, name='scanner'),
    path('login/', views.login_view, name='login'),
    path('config/', views.scan_configuration, name='configuration'),
    path('scans/', views.show_all_scans, name='scans'),
    path('add-scan/', views.add_scan, name='add_scan'),
    path('add-scan/<int:scan_id>/', views.add_scan, name='add_scan'),
    path('delete-scan/<int:scan_id>/', views.delete_scan, name='delete_scan'),
    path('register/', views.register_user, name="register"),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('pages/<str:html>/', views.pages, name='pages')
]