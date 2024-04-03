from django.contrib import admin
from .models import Seller,Deliveryreview
from .models import Certification
from .models import Category, Product, UserProfile, Assigndeliveryagent,UserAgentDistance
from .models import ProductSummary,Recommend,UserSellerDistance,Notification,DeliveryAgent

# Register your models here.
admin.site.register(Seller)

@admin.register(Certification)
class CertificationAdmin(admin.ModelAdmin):
    list_display = ('owner_name', 'store_name', 'expiry_date_from', 'expiry_date_to', 'certification_image', 'timestamp')
    list_filter = ('expiry_date_from', 'expiry_date_to')
    search_fields = ('owner_name', 'store_name')

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('category_name', 'category_description')  # Replace with actual field names
    list_filter = ('category_name', 'category_description')  # Add filters if needed
    search_fields = ('category_name', 'category_description')  # Add search fields if needed

@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ('product_name', 'category', 'product_price','product_image','seller','product_stock')  # Customize the fields to display
    list_filter = ('category', 'product_price')  # Add filters if needed
    search_fields = ('product_name', 'product_description')  # Add search fields if needed

@admin.register(ProductSummary)
class ProductSummaryAdmin(admin.ModelAdmin):
    list_display = ('product_name', 'total_stock')
# Register your models here.
admin.site.register(UserProfile)

from .models import Wishlist

class WishlistAdmin(admin.ModelAdmin):
    list_display = ('user', 'product', 'quantity', 'date_added')
    list_filter = ('user', 'date_added')
    search_fields = ('user__username', 'product__product_name')

admin.site.register(Wishlist, WishlistAdmin)

from django.contrib import admin
from .models import Cart, BillingDetails, Order, OrderItem,Review

admin.site.register(Review)
admin.site.register(Recommend)
admin.site.register(DeliveryAgent)

# Register the Cart model
@admin.register(Cart)
class CartAdmin(admin.ModelAdmin):
    list_display = ('user', 'product', 'quantity', 'price', 'date_added')
    list_filter = ('user', 'product')
    search_fields = ('user__username', 'product__product_name')
    list_per_page = 20

# Register the BillingDetails model
@admin.register(BillingDetails)
class BillingDetailsAdmin(admin.ModelAdmin):
    list_display = ('user', 'first_name', 'last_name', 'email', 'phone')
    search_fields = ('user__username', 'email')
    list_per_page = 20

# Register the Order model
@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ('user', 'total_price', 'order_date', 'payment_status')
    list_filter = ('user', 'payment_status')
    search_fields = ('user__username',)
    list_per_page = 20

# Register the OrderItem model
@admin.register(OrderItem)
class OrderItemAdmin(admin.ModelAdmin):
    list_display = ('order', 'product', 'seller', 'quantity', 'price', 'total_price')
    list_filter = ('order', 'product', 'seller')
    search_fields = ('order__user__username', 'product__product_name', 'seller__seller_name')
    list_per_page = 20

admin.site.register(UserSellerDistance)
admin.site.register(Notification)
admin.site.register(Assigndeliveryagent)
admin.site.register(Deliveryreview)
admin.site.register(UserAgentDistance)
