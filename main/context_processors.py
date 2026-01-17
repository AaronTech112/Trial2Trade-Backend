from .models import DiscountCode, Announcement
from django.utils import timezone

def active_discount_code(request):
    active_code = DiscountCode.objects.filter(is_active=True).order_by('-created_at').first()
    return {'active_discount_code': active_code}

def announcement_count(request):
    count = Announcement.objects.filter(is_published=True).count()
    return {'announcement_count': count}
