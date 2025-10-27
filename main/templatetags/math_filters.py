from django import template
from decimal import Decimal

register = template.Library()


def _to_decimal(value):
    if isinstance(value, Decimal):
        return value
    try:
        return Decimal(str(value))
    except Exception:
        return None


@register.filter(name="mul")
def mul(value, arg):
    """Multiply two values with Decimal fallback, return 0 on failure."""
    a = _to_decimal(value)
    b = _to_decimal(arg)
    try:
        if a is None or b is None:
            return float(value) * float(arg)
        return a * b
    except Exception:
        return 0


@register.filter(name="div")
def div(value, arg):
    """Divide value by arg safely, return 0 for division by zero or failure."""
    a = _to_decimal(value)
    b = _to_decimal(arg)
    try:
        if a is None or b is None:
            denom = float(arg)
            if denom == 0:
                return 0
            return float(value) / denom
        if b == 0:
            return 0
        return a / b
    except Exception:
        return 0


@register.filter(name="sub")
def sub(value, arg):
    """Subtract arg from value safely."""
    a = _to_decimal(value)
    b = _to_decimal(arg)
    try:
        if a is None or b is None:
            return float(value) - float(arg)
        return a - b
    except Exception:
        return 0


@register.filter(name="split")
def split(value, sep=" "):
    """Split string into list by separator."""
    try:
        return str(value).split(str(sep))
    except Exception:
        return []