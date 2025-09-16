# What is the shortest possible route the salesman can take, and what is the total distance?

Answer : ACEDFBA

# Email Validation Service

A production-ready, scalable email validation API similar to NeverBounce and ZeroBounce.  
Provides **format validation, DNS checks, SMTP deliverability testing, and security analysis**.

---

## Features

- Email format validation (RFC-compliant)
- DNS & MX record verification
- SMTP deliverability testing
- SPF, DKIM, DMARC analysis
- Validation scoring (0–1.0)
- Bulk & async processing
- Rate limiting & caching

---

## Tech Stack

- **Framework**: Django + DRF
- **Async**: asyncio
- **DNS**: dnspython
- **SMTP**: smtplib
- **DB**: SQLite / PostgreSQL
- **Cache/Queue**: Redis + Celery

---

## Prerequisites

- Python 3.8+
- pip
- Git

---

## Quick Setup

```bash
git clone https://github.com/yourusername/email-validation-service.git
cd email-validation-service
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```
