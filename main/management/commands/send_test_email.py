from django.core.management.base import BaseCommand, CommandError
from django.core.mail import send_mail
from django.conf import settings
import requests


class Command(BaseCommand):
    help = 'Send a test email using current EMAIL_* settings, with optional Resend fallback.'

    def add_arguments(self, parser):
        parser.add_argument('--to', dest='to', required=True, help='Recipient email address')
        parser.add_argument('--subject', dest='subject', default='Test Email', help='Email subject')
        parser.add_argument('--message', dest='message', default='This is a test email from Trial 2 Trade.', help='Email body')
        parser.add_argument('--from-email', dest='from_email', default=settings.DEFAULT_FROM_EMAIL, help='From address')
        parser.add_argument('--use-resend', dest='use_resend', action='store_true', help='Use Resend fallback if SMTP fails')

    def handle(self, *args, **options):
        to_addr = options['to']
        subject = options['subject']
        message = options['message']
        from_email = options['from_email']
        use_resend = options['use_resend']

        self.stdout.write(f"Using backend: {settings.EMAIL_BACKEND}")
        self.stdout.write(f"SMTP host: {getattr(settings, 'EMAIL_HOST', '')}:{getattr(settings, 'EMAIL_PORT', '')} TLS={getattr(settings, 'EMAIL_USE_TLS', '')}")
        self.stdout.write(f"From: {from_email} -> To: {to_addr}")
        try:
            sent = send_mail(subject, message, from_email, [to_addr], fail_silently=False)
            if sent:
                self.stdout.write(self.style.SUCCESS(f"Successfully sent {sent} email(s) via SMTP"))
                return
            else:
                self.stdout.write(self.style.WARNING('send_mail returned 0; attempting fallback if enabled'))
        except Exception as e:
            self.stdout.write(self.style.WARNING(f"SMTP sending failed: {e}"))

        if use_resend and getattr(settings, 'RESEND_API_KEY', None):
            try:
                payload = {
                    'from': from_email,
                    'to': to_addr,
                    'subject': subject,
                    'text': message,
                }
                headers = {
                    'Authorization': f"Bearer {settings.RESEND_API_KEY}",
                    'Content-Type': 'application/json',
                }
                resp = requests.post('https://api.resend.com/emails', json=payload, headers=headers, timeout=30)
                if resp.status_code in (200, 201):
                    self.stdout.write(self.style.SUCCESS("Successfully sent email via Resend fallback"))
                else:
                    raise CommandError(f"Resend fallback failed ({resp.status_code}): {resp.text}")
            except Exception as e:
                raise CommandError(f"Resend fallback error: {e}")
        else:
            raise CommandError("SMTP failed and Resend fallback not enabled or missing RESEND_API_KEY.")