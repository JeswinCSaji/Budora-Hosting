
from django.db import models
from django.contrib.auth.models import User
from django.db.models import Sum
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.contrib.auth import get_user_model

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100,null=True, blank=True)
    email = models.EmailField(max_length=255,null=True, blank=True)
    profile_pic = models.ImageField(upload_to='profile_pics/', null=True, blank=True)
    # gender = models.CharField(max_length=10, choices=GENDER_CHOICES)
    phone_number = models.CharField(max_length=20, null=True, blank=True)
    address = models.TextField(blank=True, null=True) 
    reset_password = models.CharField(max_length=128, null=True, blank=True)  # New field for reset password 
    latitude = models.DecimalField(max_digits=20, decimal_places=15, default=0.0,null=True, blank=True)
    longitude = models.DecimalField(max_digits=20, decimal_places=15, default=0.0,null=True, blank=True)
    def __str__(self):
        return self.name

class Seller(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    # approved = models.BooleanField(default=False)
    name = models.CharField(max_length=100,null=True, blank=True)
    email = models.EmailField(max_length=255,null=True, blank=True)
    storename = models.CharField(max_length=100)
    contact = models.CharField(max_length=20, null=True, blank=True)
    address = models.TextField(blank=True, null=True)
    landmark = models.TextField(blank=True, null=True)
    latitude = models.CharField(max_length=20,null=True,blank=True)
    longitude = models.CharField(max_length=20,null=True,blank=True)
    # New fields
    opening_time = models.TimeField(null=True, blank=True)
    closing_time = models.TimeField(null=True, blank=True)
    opening_days = models.CharField(max_length=100, null=True, blank=True)
    store_image = models.ImageField(upload_to='store_images/', null=True, blank=True)
    avgrating = models.IntegerField(null=True, blank=True)
    

    def str(self):
        return self.user.username

class DeliveryAgent(models.Model): 
    UPDATED = 'updated'
    NOTUPDATED = 'notupdated'
    
    APPROVAL_CHOICES = [
        (UPDATED, 'updated'),
        (NOTUPDATED, 'notupdated'),
    ]
    AVAILABILITY_CHOICES = [
        ('available', 'Available'),
        ('not_available', 'Not Available'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100,null=True, blank=True)
    email = models.EmailField(max_length=255,null=True, blank=True)
    contact = models.CharField(max_length=20, null=True, blank=True)
    address = models.TextField(blank=True, null=True)
    license_number = models.CharField(max_length=20,unique=True)
    vechicle_type = models.CharField(max_length=255,default=1)
    latitude = models.CharField(max_length=20,null=True,blank=True)
    longitude = models.CharField(max_length=20,null=True,blank=True)
    avgrating = models.IntegerField(null=True, blank=True)
    availability = models.CharField(max_length=15, choices=AVAILABILITY_CHOICES, default='not_available')
    is_approved = models.CharField(
        max_length=10,
        choices=APPROVAL_CHOICES,
        default=NOTUPDATED,
    )

    def _str_(self):
        return self.name
    

class Certification(models.Model):
    APPROVED = 'approved'
    REJECTED = 'rejected'
    PENDING = 'pending'
    
    APPROVAL_CHOICES = [
        (APPROVED, 'Approved'),
        (REJECTED, 'Rejected'),
        (PENDING, 'Pending'),
    ]
    DAY_CHOICES = [
        ('monday', 'Monday'),
        ('tuesday', 'Tuesday'),
        ('wednesday', 'Wednesday'),
        ('thursday', 'Thursday'),
        ('friday', 'Friday'),
        ('saturday', 'Saturday'),
        ('sunday', 'Sunday'),
    ]
    # seller = models.ForeignKey(Seller, on_delete=models.CASCADE, default=Seller)

    user = models.ForeignKey(User, on_delete=models.CASCADE, default=1)
    certification_image = models.ImageField(upload_to='certification_images/', null=True, blank=True)
    owner_name = models.CharField(max_length=100)  # Change 'first_name' to 'owner_name'
    store_name = models.CharField(max_length=100)  # Add 'store_name' field
    expiry_date_from = models.DateField(null=True, blank=True)
    expiry_date_to = models.DateField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    opening_time = models.TimeField(null=True, blank=True)
    closing_time = models.TimeField(null=True, blank=True)
    opening_days = models.CharField(max_length=100, choices=DAY_CHOICES, blank=True)  # Field with day choices
    store_image = models.ImageField(upload_to='store_images/', null=True, blank=True)
    latitude = models.DecimalField(max_digits=20, decimal_places=15, default=0.0)
    longitude = models.DecimalField(max_digits=20, decimal_places=15, default=0.0)
    is_approved = models.CharField(
        max_length=10,
        choices=APPROVAL_CHOICES,
        default=PENDING,
    )
    
class Category(models.Model):
    category_name = models.CharField(max_length=100)
    category_description = models.TextField()
    # default_product_price = models.DecimalField(max_digits=10, decimal_places=2)
    # category_image = models.ImageField(upload_to='category_images/', null=True, blank=True)  # Default product price for this category
    # Other fields for the category...

    def __str__(self):
        return self.category_name

class Product(models.Model):
    product_name = models.CharField(max_length=100)  # Product name selected by the seller
    category = models.ForeignKey(Category, on_delete=models.CASCADE)  # Reference to the category
    product_price = models.DecimalField(max_digits=10, decimal_places=2)  # Product price inherited from the category
    product_image = models.ImageField(upload_to='category_images/', null=True, blank=True)
    product_stock = models.IntegerField(default=0, null=True, blank=True)  # Add the default value here

    seller = models.ForeignKey(Seller, on_delete=models.CASCADE, related_name='products')

    
    def __str__(self):
        return self.product_name

    def save(self, *args, **kwargs):
        super(Product, self).save(*args, **kwargs)
        # After saving the product, update the ProductSummary
        summary, created = ProductSummary.objects.get_or_create(product_name=self.product_name)
        summary.update_total_stock()
        
class ProductSummary(models.Model):
    APPROVED = 'approved'
    PENDING = 'pending'
    
    STOCK_APPROVAL_CHOICES = [
        (APPROVED, 'Approved'),
        (PENDING, 'Pending'),
    ]

    product_name = models.CharField(max_length=100, unique=True)
    product_sci_name = models.CharField(max_length=100, blank=True, null=True)
    total_stock = models.IntegerField(default=0, null=True, blank=True)
    product_image = models.ImageField(upload_to='product_images/', blank=True, null=True)
    product_description = models.TextField(blank=True, null=True)
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, blank=True, null=True, related_name='product_summaries')
    
    # Additional fields
    light_requirements = models.CharField(max_length=100, blank=True, null=True)
    water_requirements = models.CharField(max_length=100, blank=True, null=True)
    humidity_requirements = models.CharField(max_length=100, blank=True, null=True)
    soil_type = models.CharField(max_length=100, blank=True, null=True)
    toxicity_information = models.TextField( blank=True, null=True)
    maintenance_instructions = models.TextField(blank=True, null=True)
    product = models.ForeignKey(Product, on_delete=models.CASCADE, blank=True, null=True,related_name='product_summary')
    stock_is_approved = models.CharField(
        max_length=20,
        choices=STOCK_APPROVAL_CHOICES,
        default=PENDING,
    )
    def __str__(self):
        return self.product_name

    def update_total_stock(self):
        # Calculate the total stock for this product name from the Product model
        total_stock = Product.objects.filter(product_name=self.product_name).aggregate(total_stock=Sum('product_stock'))['total_stock']
        self.total_stock = total_stock or 0
        self.save()
    @receiver(post_save, sender=Product)
    @receiver(post_delete, sender=Product)
    def update_product_summary(sender, instance, **kwargs):
        product_name = instance.product_name

        # Calculate the total stock for the given product name
        total_stock = Product.objects.filter(product_name=product_name).aggregate(total_stock=Sum('product_stock'))['total_stock']

        # Update or create the corresponding ProductSummary instance
        product_summary, created = ProductSummary.objects.get_or_create(product_name=product_name)
        product_summary.total_stock = total_stock or 0
        product_summary.save()

    @property
    def is_staff(self):
        return self.is_admin

class Wishlist(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    product = models.ForeignKey(ProductSummary, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)
    date_added = models.DateTimeField(auto_now_add=True)
    price = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    image = models.ImageField(upload_to='Wishlist_item_images/', blank=True, null=True)  # Add image field

    def __str__(self):
        return f"{self.user.username}'s Wishlist Item - {self.product.product_name}"
    
class Cart(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    seller = models.ForeignKey(Seller, on_delete=models.CASCADE, null=True)  # Assuming the seller is also a User
    quantity = models.PositiveIntegerField(default=1)
    date_added = models.DateTimeField(auto_now_add=True)
    price = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    image = models.ImageField(upload_to='cart_item_images/', blank=True, null=True)  # Add image field

    def __str__(self):
        return f"{self.user.username}'s Cart Item - {self.product.product_name}"

    def save(self, *args, **kwargs):
        # Calculate the price based on the product's price per kg and the quantity
        self.price = self.product.product_price * self.quantity
        super().save(*args, **kwargs)

class BillingDetails(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # If you want to associate the billing details with a user
    first_name = models.CharField(max_length=255, blank=True, null=True)
    last_name = models.CharField(max_length=255, blank=True, null=True)
    state = models.CharField(max_length=255, blank=True, null=True)
    street_address = models.CharField(max_length=255, blank=True, null=True)
    apartment_suite_unit = models.CharField(max_length=255, blank=True, null=True)  # Optional field
    town_city = models.CharField(max_length=255, blank=True, null=True)
    postcode_zip = models.CharField(max_length=20, blank=True, null=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    email = models.EmailField(blank=True, null=True)
    latitude = models.DecimalField(max_digits=20, decimal_places=15, default=0.0,null=True, blank=True)
    longitude = models.DecimalField(max_digits=20, decimal_places=15, default=0.0,null=True, blank=True)

    def __str__(self):
        return f"{self.first_name} {self.last_name}'s Billing Details"
    

class Order(models.Model):
    class PaymentStatusChoices(models.TextChoices):
        PENDING = 'pending', 'Pending'
        SUCCESSFUL = 'successful', 'Successful'
        FAILED = 'failed', 'Failed'

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    products = models.ManyToManyField(Product)  # Assuming you have a Product model
    seller = models.ForeignKey(Seller, on_delete=models.CASCADE, null=True)  # Assuming the seller is also a User
    total_price = models.DecimalField(max_digits=10, decimal_places=2)
    order_date = models.DateTimeField(auto_now_add=True)
    razorpay_order_id = models.CharField(max_length=255, default=None, unique=True)
    payment_status = models.CharField(
        max_length=20, choices=PaymentStatusChoices.choices, default=PaymentStatusChoices.PENDING)
    def _str_(self):
        return self.user.username 
        
class OrderItem(models.Model):
    APPROVED = 'approved'
    PENDING = 'pending'
    
    SELLER_APPROVAL_CHOICES = [
        (APPROVED, 'Approved'),
        (PENDING, 'Pending'),
    ]

    DELIVERED = 'delivered'
    NOTDELIVERED = 'notdelivered'

    AGENT_APPROVAL_CHOICES = [
        (DELIVERED, 'delivered'),
        (NOTDELIVERED, 'notdelivered'),
    ]

    ORDER = 'order'
    RESERVE = 'reserve'
    PENDING = 'pending'

    DELIVERY_CHOICES = [
        (ORDER, 'order'),
        (RESERVE, 'reserve'),
        (PENDING, 'Pending'),
    ]

    COLLECTED = 'collected'
    NOTCOLLECTED = 'notcollected'

    CUSTOMER_APPROVAL_CHOICES = [
        (COLLECTED, 'collected'),
        (NOTCOLLECTED, 'notcollected'),
    ]

    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    seller = models.ForeignKey(Seller, on_delete=models.CASCADE)  # Assuming the seller is also a User
    quantity = models.PositiveIntegerField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    total_price = models.DecimalField(max_digits=10, decimal_places=2)
    deliveryagent = models.ForeignKey(DeliveryAgent, on_delete=models.CASCADE, null=True, blank=True)
    
    order_confirmed = models.BooleanField(default=False)
    order_confirmed_date = models.DateTimeField(null=True, blank=True)

    order_processed = models.BooleanField(default=False)
    order_processed_date = models.DateTimeField(null=True, blank=True)

    order_qualitycheck = models.BooleanField(default=False)
    order_qualitycheck_date = models.DateTimeField(null=True, blank=True)

    product_dispatched = models.BooleanField(default=False)
    product_dispatched_date = models.DateTimeField(null=True, blank=True)

    delivery_order_confirmed = models.BooleanField(default=False)
    delivery_order_confirmed_date = models.DateTimeField(null=True, blank=True)

    delivered_date = models.DateTimeField(null=True, blank=True)

    waiting_pickup = models.BooleanField(default=False)
    waiting_pickup_date = models.DateTimeField(null=True, blank=True)

    order_not_valid = models.BooleanField(default=False)

    selected_date = models.DateField(blank=True, null=True) 
    seller_is_approved = models.CharField(
        max_length=20,
        choices=SELLER_APPROVAL_CHOICES,
        default=PENDING,
    )
    delivery_choice = models.CharField(
        max_length=20,
        choices=DELIVERY_CHOICES,
        default=PENDING,
    )
    customer_is_approved = models.CharField(
        max_length=20,
        choices=CUSTOMER_APPROVAL_CHOICES,
        default=NOTCOLLECTED,
    )

    agent_is_approved = models.CharField(
            max_length=20,
            choices=AGENT_APPROVAL_CHOICES,
            default=NOTDELIVERED,
        )

    def save(self, *args, **kwargs):
        # Calculate the total price for this order item based on quantity and price
        self.total_price = self.quantity * self.price
        super(OrderItem, self).save(*args, **kwargs)
        
        # Update the total order price in the associated Order model
        order = self.order
        order.total_order_price = sum(order_item.total_price for order_item in order.orderitem_set.all())
        order.save()

class Review(models.Model):
    REVIEWED = 'reviewed'
    PENDING = 'pending'
    
    REVIEW_CHOICES = [
        (REVIEWED, 'reviewed'),
        (PENDING, 'Pending'),
    ]

    review_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    seller = models.ForeignKey(Seller, on_delete=models.CASCADE)
    rating = models.IntegerField()
    outof_rating = models.IntegerField(default=5, editable=False)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    review_status = models.CharField(
        max_length=20,
        choices=REVIEW_CHOICES,
        default=PENDING,
    )


    def _str_(self):
        return f"Review by {self.user.username}"


class Deliveryreview(models.Model):
    REVIEWED = 'reviewed'
    PENDING = 'pending'
    
    REVIEW_CHOICES = [
        (REVIEWED, 'reviewed'),
        (PENDING, 'Pending'),
    ]

    review_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    deliveryagent = models.ForeignKey(DeliveryAgent, on_delete=models.CASCADE)
    rating = models.IntegerField()
    outof_rating = models.IntegerField(default=5, editable=False)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    review_status = models.CharField(
        max_length=20,
        choices=REVIEW_CHOICES,
        default=PENDING,
    )


    def _str_(self):
        return f"Review by {self.user.username}"
    
class Recommend(models.Model):
    s1 = models.CharField(max_length=200)
    s2 = models.CharField(max_length=200)
    s3 = models.CharField(max_length=200)
    s4 = models.CharField(max_length=200)
    s5 = models.CharField(max_length=200)
    plant = models.CharField(max_length=200)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.plant
    
class UserSellerDistance(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    seller = models.ForeignKey(Seller, on_delete=models.CASCADE)
    distance = models.FloatField(null=True, blank=True)

    class Meta:
        unique_together = ('user', 'seller')  

class UserAgentDistance(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE,null=True, blank=True)
    agent = models.ForeignKey(DeliveryAgent, on_delete=models.CASCADE,null=True, blank=True)
    distance = models.FloatField(null=True, blank=True)

    class Meta:
        unique_together = ('user', 'agent')  

class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE,blank=True, null=True)
    title = models.CharField(max_length=200,blank=True, null=True)
    message = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)
    def __str__(self):
        return self.title
    
class Assigndeliveryagent(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE,blank=True, null=True)
    seller = models.ForeignKey(Seller, on_delete=models.CASCADE)
    billingdetails = models.ForeignKey(BillingDetails, on_delete=models.CASCADE)
    deliveryagent =  models.ForeignKey(DeliveryAgent, on_delete=models.CASCADE)
    order = models.ForeignKey(Order, on_delete=models.CASCADE,null=True, blank=True )
    timestamp = models.DateTimeField(auto_now_add=True,null=True, blank=True)
    assigned_timestamp = models.DateTimeField(null=True, blank=True)


 




