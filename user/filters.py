# user/filters.py

from django import template

register = template.Library()

@register.filter
def is_profile_updated_message(message):
    return "Profile updated successfully" in message.tags
