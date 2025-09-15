# Enhanced serializers.py with SMTP response details
from rest_framework import serializers

class EmailValidationRequestSerializer(serializers.Serializer):
    emails = serializers.ListField(
        child=serializers.EmailField(),
        min_length=1,
        max_length=50,  # Reduced for SMTP testing
        help_text="List of email addresses to validate (max 50 for SMTP verification)"
    )
    skip_smtp = serializers.BooleanField(
        default=False,
        help_text="Skip SMTP verification for faster DNS-only validation"
    )

class ValidationResultSerializer(serializers.Serializer):
    email = serializers.EmailField()
    is_valid_format = serializers.BooleanField()
    is_deliverable = serializers.BooleanField(allow_null=True)
    smtp_status = serializers.CharField()
    smtp_response_code = serializers.IntegerField(allow_null=True)
    smtp_response_message = serializers.CharField(allow_null=True)
    domain_info = serializers.JSONField()
    spf_record = serializers.JSONField(allow_null=True)
    dkim_valid = serializers.JSONField(allow_null=True)
    dmarc_record = serializers.JSONField(allow_null=True)
    validation_score = serializers.FloatField()
    error_message = serializers.CharField(allow_null=True, required=False)

class EmailValidationResponseSerializer(serializers.Serializer):
    results = ValidationResultSerializer(many=True)
    total_count = serializers.IntegerField()
    deliverable_count = serializers.IntegerField()
    undeliverable_count = serializers.IntegerField()
    unknown_count = serializers.IntegerField()
    processing_time = serializers.FloatField()
    smtp_verification = serializers.BooleanField()

class EmailSecurityReportSerializer(serializers.Serializer):
    """Detailed security report for domain"""
    domain = serializers.CharField()
    has_spf = serializers.BooleanField()
    spf_policy = serializers.CharField(allow_null=True)
    has_dmarc = serializers.BooleanField()
    dmarc_policy = serializers.CharField(allow_null=True)
    has_dkim = serializers.BooleanField()
    dkim_selectors = serializers.ListField(child=serializers.CharField(), allow_empty=True)
    security_score = serializers.FloatField()
    recommendations = serializers.ListField(child=serializers.CharField())