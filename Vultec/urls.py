from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
from django.urls import path, include
from scanner import views

urlpatterns = [
    path('', views.index, name='index'),
    path('scanner/', include('scanner.urls')),
    path('admin/', admin.site.urls),
]

urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)