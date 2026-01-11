from .models import DiscountCode

def active_discount_code(request):
    active_code = DiscountCode.objects.filter(is_active=True).order_by('-created_at').first()
    return {'active_discount_code': active_code}
