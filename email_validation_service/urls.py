from django.contrib import admin
from django.urls import path, include
from django.http import JsonResponse
from django.views import View

class HomeView(View):
    def get(self, request):
        return JsonResponse({
            "message": "Email Validation Service API v2.0",
            "endpoints": {
                "validate": "/api/v1/email/validate/",
                "domain_security": "/api/v1/email/domain-security/?domain=example.com",
                "health": "/api/v1/email/health/",
                "batch_info": "/api/v1/email/batch-info/?batch_size=10",
                "admin": "/admin/"
            },
            "features": [
                "Real SMTP deliverability testing",
                "Enhanced DNS record analysis", 
                "SPF/DMARC/DKIM verification",
                "Domain security reports"
            ],
            "version": "2.0.0"
        })

urlpatterns = [
    path('', HomeView.as_view(), name='home'),
    path('admin/', admin.site.urls),
    path('api/v1/email/', include('email_validator_app.urls')),
]