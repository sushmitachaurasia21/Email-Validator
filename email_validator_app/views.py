# Enhanced views.py with full SMTP validation
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.throttling import AnonRateThrottle
import asyncio
import time
from .validators import EmailValidator
from .serializers import (
    EmailValidationRequestSerializer,
    EmailValidationResponseSerializer,
    EmailSecurityReportSerializer
)
import logging

logger = logging.getLogger(__name__)

class EmailValidationView(APIView):
    throttle_classes = [AnonRateThrottle]
    
    def post(self, request):
        """Validate email addresses with full SMTP verification"""
        serializer = EmailValidationRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"error": "Invalid request", "details": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        emails = serializer.validated_data['emails']
        skip_smtp = serializer.validated_data.get('skip_smtp', False)
        start_time = time.time()
        
        # Warn about SMTP validation time
        if not skip_smtp and len(emails) > 10:
            logger.info(f"SMTP validation for {len(emails)} emails may take 30-60 seconds...")
        
        # Run async validation
        try:
            if skip_smtp:
                # Use the old fast method for DNS-only validation
                validator = EmailValidator()
                # Temporarily disable SMTP for speed
                validator._validate_smtp_deliverability = self._mock_smtp_validation
                
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                validator = EmailValidator()
                validation_results = loop.run_until_complete(
                    validator.validate_emails(emails)
                )
            finally:
                loop.close()
                
        except Exception as e:
            logger.error(f"Validation error: {e}")
            return Response(
                {"error": "Validation failed", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        processing_time = time.time() - start_time
        
        # Calculate statistics
        total_count = len(validation_results)
        deliverable_count = sum(1 for r in validation_results if r.is_deliverable is True)
        undeliverable_count = sum(1 for r in validation_results if r.is_deliverable is False)
        unknown_count = sum(1 for r in validation_results if r.is_deliverable is None)
        
        # Prepare response
        results_data = []
        for result in validation_results:
            results_data.append({
                'email': result.email,
                'is_valid_format': result.is_valid_format,
                'is_deliverable': result.is_deliverable,
                'smtp_status': result.smtp_status,
                'smtp_response_code': result.smtp_response_code,
                'smtp_response_message': result.smtp_response_message,
                'domain_info': result.domain_info,
                'spf_record': result.spf_record,
                'dkim_valid': result.dkim_valid,
                'dmarc_record': result.dmarc_record,
                'validation_score': result.validation_score,
                'error_message': getattr(result, 'error_message', None)
            })
        
        response_data = {
            'results': results_data,
            'total_count': total_count,
            'deliverable_count': deliverable_count,
            'undeliverable_count': undeliverable_count,
            'unknown_count': unknown_count,
            'processing_time': processing_time,
            'smtp_verification': not skip_smtp
        }
        
        response_serializer = EmailValidationResponseSerializer(response_data)
        return Response(response_serializer.data)
    
    async def _mock_smtp_validation(self, email: str, mx_records: list) -> dict:
        """Mock SMTP validation for DNS-only mode"""
        if mx_records:
            return {
                'is_deliverable': True,
                'status': 'dns_only_check',
                'response_code': None,
                'response_message': 'SMTP verification skipped - DNS validation only'
            }
        else:
            return {
                'is_deliverable': False,
                'status': 'no_mx_records',
                'response_code': None,
                'response_message': 'No MX records found'
            }

class DomainSecurityReportView(APIView):
    """Get detailed security report for a domain"""
    
    def get(self, request):
        domain = request.query_params.get('domain')
        if not domain:
            return Response(
                {"error": "Domain parameter is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                validator = EmailValidator()
                domain_info = loop.run_until_complete(
                    validator._validate_domain(domain)
                )
            finally:
                loop.close()
            
            # Generate security report
            report = self._generate_security_report(domain, domain_info)
            
            serializer = EmailSecurityReportSerializer(report)
            return Response(serializer.data)
            
        except Exception as e:
            logger.error(f"Domain security report error: {e}")
            return Response(
                {"error": "Failed to generate security report", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _generate_security_report(self, domain: str, domain_info: dict) -> dict:
        """Generate comprehensive security report"""
        spf_info = domain_info.get('spf_record')
        dmarc_info = domain_info.get('dmarc_record')
        dkim_info = domain_info.get('dkim_valid')
        
        has_spf = spf_info is not None
        has_dmarc = dmarc_info is not None
        has_dkim = dkim_info is not None
        
        # Calculate security score
        security_score = 0.0
        if has_spf:
            security_score += 0.3
            if isinstance(spf_info, dict) and spf_info.get('policy') == 'strict':
                security_score += 0.1
        
        if has_dmarc:
            security_score += 0.4
            if isinstance(dmarc_info, dict):
                policy = dmarc_info.get('policy', {}).get('alignment', 'none')
                if policy == 'quarantine':
                    security_score += 0.1
                elif policy == 'reject':
                    security_score += 0.2
        
        if has_dkim:
            security_score += 0.3
        
        # Generate recommendations
        recommendations = []
        if not has_spf:
            recommendations.append("Add SPF record to prevent email spoofing")
        elif isinstance(spf_info, dict) and spf_info.get('policy') in ['permissive', 'unknown']:
            recommendations.append("Strengthen SPF policy to use '-all' instead of '+all' or '?all'")
        
        if not has_dmarc:
            recommendations.append("Implement DMARC policy for email authentication")
        elif isinstance(dmarc_info, dict):
            policy = dmarc_info.get('policy', {}).get('alignment', 'none')
            if policy == 'none':
                recommendations.append("Upgrade DMARC policy from 'none' to 'quarantine' or 'reject'")
            elif policy == 'quarantine':
                recommendations.append("Consider upgrading DMARC policy to 'reject' for maximum protection")
        
        if not has_dkim:
            recommendations.append("Set up DKIM signing to authenticate your emails")
        elif isinstance(dkim_info, dict) and len(dkim_info.get('selectors_found', [])) == 1:
            recommendations.append("Consider setting up multiple DKIM selectors for redundancy")
        
        if security_score >= 0.9:
            recommendations.append("Excellent email security configuration!")
        elif security_score >= 0.7:
            recommendations.append("Good email security - consider implementing missing recommendations")
        else:
            recommendations.append("Email security needs improvement - implement SPF, DKIM, and DMARC")
        
        return {
            'domain': domain,
            'has_spf': has_spf,
            'spf_policy': spf_info.get('policy') if isinstance(spf_info, dict) else None,
            'has_dmarc': has_dmarc,
            'dmarc_policy': dmarc_info.get('policy', {}).get('alignment') if isinstance(dmarc_info, dict) else None,
            'has_dkim': has_dkim,
            'dkim_selectors': dkim_info.get('selectors_found', []) if isinstance(dkim_info, dict) else [],
            'security_score': round(security_score, 2),
            'recommendations': recommendations
        }

class HealthCheckView(APIView):
    def get(self, request):
        return Response({
            "status": "healthy", 
            "service": "email-validator-pro",
            "features": [
                "Email format validation",
                "DNS/MX record verification", 
                "Full SMTP deliverability testing",
                "SPF record analysis",
                "DMARC policy detection",
                "DKIM signature verification",
                "Domain security reporting"
            ],
            "version": "2.0.0"
        })

class BulkValidationStatusView(APIView):
    """Check validation progress for large batches"""
    
    def get(self, request):
        batch_size = int(request.query_params.get('batch_size', 10))
        
        if batch_size <= 10:
            estimated_time = "5-15 seconds"
        elif batch_size <= 50:
            estimated_time = "30-90 seconds"
        else:
            estimated_time = "2-5 minutes"
        
        return Response({
            "batch_size": batch_size,
            "estimated_time": estimated_time,
            "recommendation": "Use 'skip_smtp': true for faster DNS-only validation of large batches",
            "smtp_note": "SMTP validation provides the most accurate deliverability results but takes longer"
        })