# Enhanced validators.py with real SMTP validation
import asyncio
import smtplib
import socket
import dns.resolver
from email_validator import validate_email, EmailNotValidError
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from django.core.cache import cache
import logging
import re

logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    email: str
    is_valid_format: bool
    is_deliverable: bool
    smtp_status: str
    smtp_response_code: Optional[int]
    smtp_response_message: Optional[str]
    domain_info: Dict[str, Any]
    spf_record: Optional[str]
    dkim_valid: Optional[bool]
    dmarc_record: Optional[str]
    validation_score: float
    error_message: Optional[str] = None

class EmailValidator:
    def __init__(self):
        self.smtp_timeout = 15
        self.max_concurrent_smtp = 10
        self.sender_email = "validator@yourdomain.com"  # Fake sender for validation
        self.sender_domain = "yourdomain.com"

    async def validate_emails(self, emails: List[str]) -> List[ValidationResult]:
        """Validate multiple emails concurrently"""
        # Use semaphore to limit concurrent SMTP connections
        semaphore = asyncio.Semaphore(self.max_concurrent_smtp)
        
        async def validate_with_semaphore(email):
            async with semaphore:
                return await self.validate_single_email(email)
        
        tasks = [validate_with_semaphore(email) for email in emails]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        validated_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Error validating {emails[i]}: {result}")
                validated_results.append(ValidationResult(
                    email=emails[i],
                    is_valid_format=False,
                    is_deliverable=False,
                    smtp_status="error",
                    smtp_response_code=None,
                    smtp_response_message=str(result),
                    domain_info={},
                    spf_record=None,
                    dkim_valid=None,
                    dmarc_record=None,
                    validation_score=0.0,
                    error_message=str(result)
                ))
            else:
                validated_results.append(result)
        
        return validated_results

    async def validate_single_email(self, email: str) -> ValidationResult:
        """Validate a single email address with full SMTP verification"""
        try:
            # Step 1: Format validation
            is_valid_format, normalized_email = self._validate_format(email)
            if not is_valid_format:
                return ValidationResult(
                    email=email,
                    is_valid_format=False,
                    is_deliverable=False,
                    smtp_status="invalid_format",
                    smtp_response_code=None,
                    smtp_response_message="Email format is invalid",
                    domain_info={},
                    spf_record=None,
                    dkim_valid=None,
                    dmarc_record=None,
                    validation_score=0.0
                )

            domain = normalized_email.split('@')[1]
            
            # Step 2: DNS and domain validation
            domain_info = await self._validate_domain(domain)
            if not domain_info.get('has_mx_records'):
                return ValidationResult(
                    email=normalized_email,
                    is_valid_format=True,
                    is_deliverable=False,
                    smtp_status="no_mx_records",
                    smtp_response_code=None,
                    smtp_response_message="No MX records found for domain",
                    domain_info=domain_info,
                    spf_record=domain_info.get('spf_record'),
                    dkim_valid=domain_info.get('dkim_valid'),
                    dmarc_record=domain_info.get('dmarc_record'),
                    validation_score=0.2
                )

            # Step 3: SMTP validation (the real test!)
            smtp_result = await self._validate_smtp_deliverability(
                normalized_email, domain_info.get('mx_records', [])
            )

            # Step 4: Calculate validation score
            validation_score = self._calculate_score(
                is_valid_format, 
                smtp_result['is_deliverable'], 
                smtp_result['status'], 
                domain_info
            )

            return ValidationResult(
                email=normalized_email,
                is_valid_format=True,
                is_deliverable=smtp_result['is_deliverable'],
                smtp_status=smtp_result['status'],
                smtp_response_code=smtp_result.get('response_code'),
                smtp_response_message=smtp_result.get('response_message'),
                domain_info=domain_info,
                spf_record=domain_info.get('spf_record'),
                dkim_valid=domain_info.get('dkim_valid'),
                dmarc_record=domain_info.get('dmarc_record'),
                validation_score=validation_score
            )

        except Exception as e:
            logger.error(f"Unexpected error validating {email}: {e}")
            return ValidationResult(
                email=email,
                is_valid_format=False,
                is_deliverable=False,
                smtp_status="validation_error",
                smtp_response_code=None,
                smtp_response_message=str(e),
                domain_info={},
                spf_record=None,
                dkim_valid=None,
                dmarc_record=None,
                validation_score=0.0,
                error_message=str(e)
            )

    def _validate_format(self, email: str) -> tuple:
        """Validate email format"""
        try:
            # Basic format checks
            if not email or '@' not in email or email.count('@') != 1:
                return False, email
            
            local, domain = email.split('@', 1)
            if not local or not domain or len(local) > 64 or len(domain) > 253:
                return False, email
            
            # Use email-validator library
            valid = validate_email(email, check_deliverability=False)
            return True, valid.email
        except EmailNotValidError as e:
            return False, email
        except Exception as e:
            return False, email

    async def _validate_domain(self, domain: str) -> Dict[str, Any]:
        """Validate domain and fetch comprehensive DNS records"""
        cache_key = f"domain_full:{domain}"
        cached_result = cache.get(cache_key)
        if cached_result:
            return cached_result

        domain_info = {
            'domain': domain,
            'has_mx_records': False,
            'mx_records': [],
            'a_records': [],
            'spf_record': None,
            'dmarc_record': None,
            'dkim_valid': None,
            'dns_valid': True
        }

        try:
            # Get MX records
            mx_records = self._get_mx_records_sync(domain)
            domain_info['mx_records'] = mx_records
            domain_info['has_mx_records'] = len(mx_records) > 0

            # Get A records (fallback for direct delivery)
            a_records = self._get_a_records_sync(domain)
            domain_info['a_records'] = a_records

            # Get SPF record
            spf_record = self._get_spf_record_sync(domain)
            domain_info['spf_record'] = spf_record

            # Get DMARC record
            dmarc_record = self._get_dmarc_record_sync(domain)
            domain_info['dmarc_record'] = dmarc_record

            # Enhanced DKIM check
            dkim_valid = self._check_dkim_comprehensive(domain)
            domain_info['dkim_valid'] = dkim_valid

            # Cache for 2 hours
            cache.set(cache_key, domain_info, 7200)

        except Exception as e:
            logger.error(f"Error validating domain {domain}: {e}")
            domain_info['dns_valid'] = False

        return domain_info

    def _get_mx_records_sync(self, domain: str) -> List[Dict[str, Any]]:
        """Get MX records with priority"""
        try:
            result = dns.resolver.resolve(domain, 'MX')
            mx_records = []
            for rdata in result:
                mx_records.append({
                    'host': str(rdata.exchange).rstrip('.'),
                    'priority': rdata.preference
                })
            return sorted(mx_records, key=lambda x: x['priority'])
        except Exception as e:
            logger.debug(f"No MX records for {domain}: {e}")
            return []

    def _get_a_records_sync(self, domain: str) -> List[str]:
        """Get A records for domain"""
        try:
            result = dns.resolver.resolve(domain, 'A')
            return [str(rdata) for rdata in result]
        except Exception as e:
            logger.debug(f"No A records for {domain}: {e}")
            return []

    def _get_spf_record_sync(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get and parse SPF record"""
        try:
            result = dns.resolver.resolve(domain, 'TXT')
            for rdata in result:
                txt_record = str(rdata).strip('"')
                if txt_record.startswith('v=spf1'):
                    return {
                        'record': txt_record,
                        'policy': self._parse_spf_policy(txt_record)
                    }
        except Exception as e:
            logger.debug(f"No SPF record for {domain}: {e}")
        return None

    def _parse_spf_policy(self, spf_record: str) -> str:
        """Parse SPF policy (strict, moderate, permissive)"""
        if spf_record.endswith(' -all'):
            return 'strict'  # Fail all unauthorized
        elif spf_record.endswith(' ~all'):
            return 'moderate'  # Soft fail unauthorized
        elif spf_record.endswith(' +all') or spf_record.endswith(' ?all'):
            return 'permissive'  # Allow all or neutral
        else:
            return 'unknown'

    def _get_dmarc_record_sync(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get and parse DMARC record"""
        try:
            dmarc_domain = f"_dmarc.{domain}"
            result = dns.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in result:
                txt_record = str(rdata).strip('"')
                if txt_record.startswith('v=DMARC1'):
                    return {
                        'record': txt_record,
                        'policy': self._parse_dmarc_policy(txt_record)
                    }
        except Exception as e:
            logger.debug(f"No DMARC record for {domain}: {e}")
        return None

    def _parse_dmarc_policy(self, dmarc_record: str) -> Dict[str, str]:
        """Parse DMARC policy details"""
        policy_info = {}
        
        # Extract policy
        p_match = re.search(r'p=([^;]+)', dmarc_record)
        policy_info['alignment'] = p_match.group(1) if p_match else 'none'
        
        # Extract subdomain policy
        sp_match = re.search(r'sp=([^;]+)', dmarc_record)
        policy_info['subdomain_policy'] = sp_match.group(1) if sp_match else policy_info['alignment']
        
        # Extract percentage
        pct_match = re.search(r'pct=([^;]+)', dmarc_record)
        policy_info['percentage'] = pct_match.group(1) if pct_match else '100'
        
        return policy_info

    def _check_dkim_comprehensive(self, domain: str) -> Optional[Dict[str, Any]]:
        """Comprehensive DKIM check with multiple selectors"""
        common_selectors = [
            'default', 'google', 'k1', 's1', 's2', 
            'selector1', 'selector2', 'dkim', 'mail',
            '2017', '2018', '2019', '2020', '2021', '2022', '2023', '2024'
        ]
        
        dkim_info = {
            'has_dkim': False,
            'selectors_found': [],
            'key_types': []
        }
        
        for selector in common_selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                result = dns.resolver.resolve(dkim_domain, 'TXT')
                for rdata in result:
                    txt_record = str(rdata).strip('"')
                    if 'k=' in txt_record and 'p=' in txt_record:
                        dkim_info['has_dkim'] = True
                        dkim_info['selectors_found'].append(selector)
                        
                        # Extract key type
                        k_match = re.search(r'k=([^;]+)', txt_record)
                        if k_match:
                            key_type = k_match.group(1)
                            if key_type not in dkim_info['key_types']:
                                dkim_info['key_types'].append(key_type)
            except Exception:
                continue
        
        return dkim_info if dkim_info['has_dkim'] else None

    async def _validate_smtp_deliverability(self, email: str, mx_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Full SMTP validation to check if email can actually receive messages"""
        if not mx_records:
            return {
                'is_deliverable': False,
                'status': 'no_mx_records',
                'response_code': None,
                'response_message': 'No MX records found'
            }

        # Try each MX record in priority order
        for mx_record in mx_records[:3]:  # Try top 3 MX records
            try:
                mx_host = mx_record['host']
                
                # Run SMTP check in thread pool to avoid blocking
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    None, self._smtp_conversation, email, mx_host
                )
                
                # If we get a definitive answer, return it
                if result['status'] in ['deliverable', 'undeliverable', 'mailbox_full']:
                    return result
                    
            except Exception as e:
                logger.debug(f"SMTP check failed for {mx_host}: {e}")
                continue

        return {
            'is_deliverable': False,
            'status': 'smtp_unavailable',
            'response_code': None,
            'response_message': 'Could not connect to any mail server'
        }

    def _smtp_conversation(self, email: str, mx_host: str) -> Dict[str, Any]:
        """Perform actual SMTP conversation to test deliverability"""
        try:
            # Create SMTP connection
            with smtplib.SMTP(timeout=self.smtp_timeout) as smtp:
                # Connect and identify
                smtp.connect(mx_host, 25)
                smtp.helo(self.sender_domain)
                
                # Set sender
                smtp.mail(self.sender_email)
                
                # Test recipient - this is the key test!
                code, message = smtp.rcpt(email)
                message_str = message.decode('utf-8') if isinstance(message, bytes) else str(message)
                
                # Analyze SMTP response codes
                if code == 250:
                    return {
                        'is_deliverable': True,
                        'status': 'deliverable',
                        'response_code': code,
                        'response_message': message_str
                    }
                elif code == 550:
                    if any(phrase in message_str.lower() for phrase in ['user unknown', 'mailbox unavailable', 'recipient rejected']):
                        return {
                            'is_deliverable': False,
                            'status': 'undeliverable',
                            'response_code': code,
                            'response_message': message_str
                        }
                    elif 'full' in message_str.lower():
                        return {
                            'is_deliverable': False,
                            'status': 'mailbox_full',
                            'response_code': code,
                            'response_message': message_str
                        }
                elif code in [451, 452, 421]:
                    return {
                        'is_deliverable': None,  # Temporary failure
                        'status': 'temporary_failure',
                        'response_code': code,
                        'response_message': message_str
                    }
                else:
                    return {
                        'is_deliverable': False,
                        'status': f'smtp_error_{code}',
                        'response_code': code,
                        'response_message': message_str
                    }
                    
        except socket.timeout:
            return {
                'is_deliverable': False,
                'status': 'timeout',
                'response_code': None,
                'response_message': 'SMTP connection timeout'
            }
        except ConnectionRefusedError:
            return {
                'is_deliverable': False,
                'status': 'connection_refused',
                'response_code': None,
                'response_message': 'SMTP connection refused'
            }
        except smtplib.SMTPServerDisconnected:
            return {
                'is_deliverable': False,
                'status': 'server_disconnected',
                'response_code': None,
                'response_message': 'SMTP server disconnected'
            }
        except Exception as e:
            return {
                'is_deliverable': False,
                'status': 'smtp_error',
                'response_code': None,
                'response_message': str(e)
            }

    def _calculate_score(self, is_valid_format: bool, is_deliverable: Optional[bool], 
                        smtp_status: str, domain_info: Dict[str, Any]) -> float:
        """Enhanced validation score calculation"""
        score = 0.0
        
        # Format validation (20%)
        if is_valid_format:
            score += 0.20
        
        # DNS/MX records (20%)
        if domain_info.get('has_mx_records'):
            score += 0.20
        
        # SMTP deliverability (40% - most important!)
        if is_deliverable is True:
            score += 0.40
        elif is_deliverable is None:  # Temporary failure
            score += 0.20
        # else: 0 points for undeliverable
        
        # SPF record (5%)
        spf_info = domain_info.get('spf_record')
        if spf_info:
            score += 0.05
            # Bonus for strict SPF
            if isinstance(spf_info, dict) and spf_info.get('policy') == 'strict':
                score += 0.02
        
        # DMARC record (8%)
        dmarc_info = domain_info.get('dmarc_record')
        if dmarc_info:
            score += 0.05
            # Bonus for strict DMARC
            if isinstance(dmarc_info, dict):
                policy = dmarc_info.get('policy', {}).get('alignment', 'none')
                if policy in ['quarantine', 'reject']:
                    score += 0.03
        
        # DKIM (7%)
        dkim_info = domain_info.get('dkim_valid')
        if dkim_info:
            score += 0.05
            # Bonus for multiple selectors
            if isinstance(dkim_info, dict) and len(dkim_info.get('selectors_found', [])) > 1:
                score += 0.02
        
        return min(score, 1.0)