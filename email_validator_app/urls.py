# email_validator_app/urls.py - Enhanced with new endpoints
from django.urls import path
from .views import (
    EmailValidationView, 
    DomainSecurityReportView,
    HealthCheckView, 
    BulkValidationStatusView
)

urlpatterns = [
    path('validate/', EmailValidationView.as_view(), name='email-validation'),
    path('domain-security/', DomainSecurityReportView.as_view(), name='domain-security'),
    path('health/', HealthCheckView.as_view(), name='health-check'),
    path('batch-info/', BulkValidationStatusView.as_view(), name='batch-info'),
]