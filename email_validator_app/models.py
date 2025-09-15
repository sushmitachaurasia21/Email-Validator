from django.db import models
import uuid
import json

class EmailValidationResult(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField()
    is_valid_format = models.BooleanField()
    is_deliverable = models.BooleanField()
    smtp_status = models.CharField(max_length=50)
    domain_info = models.TextField(default='{}')  # JSON as text for SQLite
    spf_record = models.TextField(null=True, blank=True)
    dkim_valid = models.BooleanField(null=True)
    dmarc_record = models.TextField(null=True, blank=True)
    validation_score = models.FloatField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'email_validation_results'
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['created_at']),
        ]

    def get_domain_info(self):
        return json.loads(self.domain_info) if self.domain_info else {}
    
    def set_domain_info(self, data):
        self.domain_info = json.dumps(data)