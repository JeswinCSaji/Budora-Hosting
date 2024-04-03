import datetime
import random
import qrcode
import base64
import urllib.parse
from datetime import date
from io import BytesIO
from datetime import datetime, timedelta
from .models import UserProfile,UserSellerDistance,Notification,DeliveryAgent
from django.shortcuts import render, redirect, HttpResponse
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login as auth_login, logout, get_user_model
from django.contrib import messages
from django.http import JsonResponse
from .models import Seller,Deliveryreview
from .models import Certification,Assigndeliveryagent
from django.shortcuts import get_object_or_404
from django.db import IntegrityError  
from django.contrib.auth.decorators import login_required 
from .models import Category,Product,Wishlist,Cart
from .models import ProductSummary,UserAgentDistance
from django.core.exceptions import ValidationError
from django.contrib.auth import password_validation
from django.utils import timezone
from django.contrib.auth import update_session_auth_hash  # Add this import
from django.contrib.auth.forms import PasswordChangeForm
from django.core.mail import send_mail
from django.conf import settings
from django.db.models import Avg
from textblob import TextBlob
from django.template.loader import get_template
from xhtml2pdf import pisa  # Import for PDF generation
from math import radians,sin,cos,sqrt,atan2

def register(request):
     
    if request.method == 'POST':
        name = request.POST.get('username')
        username = request.POST.get('email')
        email = request.POST.get('email')
        password = request.POST.get('pwd')
        Cpassword = request.POST.get('cpwd')

        try:
            password_validation.validate_password(password, User)
        except ValidationError as e:
            for error in e.error_list:
                messages.error(request, error)
            return redirect('register')
        
        if password == Cpassword:
            if User.objects.filter(username=username).exists():
                messages.info(request, "Email already taken")
                return redirect('register')
            

            otp, timestamp = generate_otp()
            send_otp_email(email, otp)

            # Store the OTP in the session (you may also use a cache or database)
            request.session['registration_otp'] = otp
            request.session['registration_otp_timestamp'] = timestamp
            request.session['registration_email'] = email
            request.session['registration_name'] = name
            request.session['registration_password'] = password

            return render(request, 'otp_verification.html')
        
            # elif User.objects.filter(email=email).exists():
            #     messages.info(request, "Email already taken")
            #     return redirect('register')
            
            # else:
            #     user = User.objects.create_user(username=username, email=email,password=password)
            #     user_profile = UserProfile(user=user, email=email ,name=name)
            #     user_profile.save()


            #     subject = 'Welcome to Budora - Registration Successful'
            #     message = f'Dear {name},\n\n' \
            #             'Congratulations! You have successfully registered on Budora. Welcome to our community.\n\n' \
            #             'Thank you for choosing Budora as your platform.\n\n' \
            #             'Best regards,\n' \
            #             'The Budora Team'
            #     from_email = settings.EMAIL_HOST_USER  # Your sender email address
            #     recipient_list = [user.email]

            #     send_mail(subject, message, from_email, recipient_list)
            #     return redirect('loginu')
        else:
            messages.info(request, "Passwords do not match")
            return redirect('register')
    else:
        return render(request, 'register.html')

def generate_otp():
    # Generate a random 6-digit OTP (you can adjust the length as needed)
    otp = str(random.randint(100000, 999999))
    
    # Add a timestamp for OTP generation
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    return otp, timestamp

def send_otp_email(email, otp):
    subject = 'Budora - OTP for Registration'
    message = f'Your OTP for Budora registration is: {otp}'
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [email]

    send_mail(subject, message, from_email, recipient_list)



def verify_otp(request):
    if request.method == 'POST':
        entered_otp = request.POST.get('otp')
        stored_otp = request.session.get('registration_otp', '')
        timestamp_str  = request.session.get('registration_otp_timestamp')
        email = request.session.get('registration_email', '')
        name = request.session.get('registration_name', '')
        password = request.session.get('registration_password', '')

        if entered_otp == stored_otp:
            # OTP is valid, proceed with registration
            if timestamp_str:
                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                if (datetime.now() - timestamp).seconds <= 120:
                    user = User.objects.create_user(username=email, email=email, password=password)
                    user_profile = UserProfile(user=user, email=email, name=name)
                    user_profile.save()
                    subject = 'Welcome to Budora - Registration Successful'
                    message = f'Dear {name},\n\n' \
                                'Congratulations! You have successfully registered on Budora. Welcome to our community.\n\n' \
                                'Thank you for choosing Budora as your platform.\n\n' \
                                'Best regards,\n' \
                                'The Budora Team'
                    from_email = settings.EMAIL_HOST_USER  # Your sender email address
                    recipient_list = [user.email]

                    send_mail(subject, message, from_email, recipient_list)   
                    # Clear OTP-related session data
                    del request.session['registration_otp']
                    del request.session['registration_otp_timestamp']
                    del request.session['registration_email']

            return redirect('loginu')
        else:
            messages.error(request, "Invalid OTP. Please try again.")
            return redirect('verify_otp')  # Adjust the redirect URL as needed
    else:
        return render(request, 'otp_verification.html')

def resend_otp(request):
    email = request.session.get('registration_email', '')
    if email:
        otp, timestamp = generate_otp()
        send_otp_email(email, otp)

        # Update the OTP and timestamp in the session
        request.session['registration_otp'] = otp
        request.session['registration_otp_timestamp'] = timestamp

        messages.info(request, "OTP resent successfully.")
    else:
        messages.error(request, "Error resending OTP. Please try again.")

    return redirect('verify_otp') 

def seller_register(request):
    if request.method == 'POST':
        name = request.POST.get('username')
        username = request.POST['email']
        email = request.POST['email']
        landmark = request.POST['landmark']
        password = request.POST['pwd']
        Cpassword = request.POST.get('cpwd')
        contact = request.POST['contact']
        address = request.POST['address']
        storename = request.POST['storename']

        # Validate password strength
        try:
            password_validation.validate_password(password, User)
        except ValidationError as e:
            for error in e.error_list:
                messages.error(request, error)
            return redirect('seller_register')
        
        if password == Cpassword:
            if User.objects.filter(username=username).exists():
                messages.info(request, "Email already registered")
                return redirect('seller_register')
	        
            
                
                # Generate and send SMS OTP

                
                # Send email OTP
            otp, timestamp = generate_otp()
            send_otp_email(email, otp)
	
            request.session['registration_otp'] = otp
          
            request.session['registration_otp_timestamp'] = timestamp
            request.session['registration_email'] = email
            request.session['registration_name'] = name
            request.session['registration_password'] = password	
            request.session['registration_landmark'] = landmark
            request.session['registration_storename'] = storename
            request.session['registration_contact'] = contact
            request.session['registration_address'] = address

            return render(request, 'seller/verify_otp.html')
            
        else:
            messages.info(request, "Passwords do not match")
            return redirect('seller_register')
    else:   
        return render(request, 'seller/seller_register.html')


def verify_seller_otp(request):
    if request.method == 'POST':     
        email_otp_entered = request.POST['email_otp']
        stored_otp = request.session.get('registration_otp', '')    
        timestamp_str  = request.session.get('registration_otp_timestamp')
        email = request.session.get('registration_email', '')
        name = request.session.get('registration_name', '')
        password = request.session.get('registration_password', '')
        landmark = request.session.get('registration_landmark', '')
        storename = request.session.get('registration_storename', '')
        contact = request.session.get('registration_contact', '')
        address = request.session.get('registration_address', '')
       
        if email_otp_entered == stored_otp :
            if timestamp_str:
                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                if (datetime.now() - timestamp).seconds <= 120:
                    user = User.objects.create_user(username=email, email=email, password=password)
                    seller = Seller.objects.create(user=user,email=email ,name=name, landmark=landmark, storename=storename, contact=contact, address=address)
                    seller.save()
                    user.is_staff = True
                    user.save()
                    user_profile = UserProfile(user=user, email=email ,name=name)
                    user_profile.save()
                    subject = 'Welcome to Budora'
                    message = 'We are thrilled to welcome you to Budora! Your account registration has been completed successfully, and you are now a valued member of our community.'
                    from_email = settings.EMAIL_HOST_USER  # Your sender email address
                    recipient_list = [seller.email]

                    send_mail(subject, message, from_email, recipient_list)
 
                    # Clear OTP-related session data
                    del request.session['registration_otp']
                    del request.session['registration_otp_timestamp']
                    del request.session['registration_email']
                    del request.session['registration_contact']
		            
            return redirect('loginu')
	
                

        else:
            messages.error(request, 'Invalid email Please try again.')
            return redirect('verify_seller_otp')
    else:	
        return render(request, 'seller/verify_otp.html')

def resend_seller_otp(request):
    email = request.session.get('registration_email', '')
    if email:
        otp, timestamp = generate_otp()
        send_otp_email(email, otp)

        # Update the OTP and timestamp in the session
        request.session['registration_otp'] = otp
        request.session['registration_otp_timestamp'] = timestamp

        messages.info(request, "OTP resent successfully.")
    else:
        messages.error(request, "Error resending OTP. Please try again.")

    return redirect('verify_seller_otp') 


def loginu(request):
    login_error_message = None

    if request.method == 'POST':
        username = request.POST['email']
        password = request.POST['password']
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            auth_login(request, user)
            
            if user.is_superuser:
                request.session['user_id'] = user.id
                request.session['username'] = user.email
                return redirect('admin_index') 
            elif user.is_staff:
                request.session['user_id'] = user.id
                request.session['username'] = user.email
                return redirect('seller_index')
            else:
                if DeliveryAgent.objects.filter(user=user):
                    request.session['user_id'] = user.id
                    request.session['username'] = user.email
                    return redirect('agent_index')  # Redirect other users to index.html
                else:
                    request.session['user_id'] = user.id
                    request.session['username'] = user.email
                    return redirect('index.html') 
        else:   
            login_error_message = "Invalid Credentials"

    return render(request, 'login.html', {'login_error_message': login_error_message})


@login_required   
def admin_index(request):
    
    seller = Seller.objects.all
    agents = DeliveryAgent.objects.all
    context = {
        'seller': seller,
        'agents':agents,
    }
    return render(request, 'admin/dashadmin.html',context)


 
def product(request):
    return render(request, 'usertems/product.html')

def sample(request):
    return render(request, 'invoicesample.html')


def index(request):
    product_summaries = ProductSummary.objects.all()
    list1=[]

    if request.user.is_authenticated and not request.user.is_superuser:
        user_profile = UserProfile.objects.get(user=request.user)
        if not user_profile.address and  user_profile.phone_number is None and not user_profile.profile_pic:
            message = "Please update your profile with address, phone number, and profile picture."
            Notification.objects.update_or_create(user=request.user, title="Profile Update Required", message=message, defaults={'is_read': False})
        elif not user_profile.address and  user_profile.phone_number is None:
            message = "Please update your profile with address and phone number"
            Notification.objects.update_or_create(user=request.user, title="Profile Update Required", message=message, defaults={'is_read': False})
        elif not user_profile.profile_pic and  user_profile.phone_number is None:
            message = "Please update your profile with profile pic and phone number"
            Notification.objects.update_or_create(user=request.user, title="Profile Update Required", message=message, defaults={'is_read': False})
        elif not user_profile.profile_pic and not user_profile.address:
            message = "Please update your profile with address and profile pic"
            Notification.objects.update_or_create(user=request.user, title="Profile Update Required", message=message, defaults={'is_read': False})
        elif not user_profile.address:
            message = "Please update your profile with address."
            Notification.objects.update_or_create(user=request.user, title="Profile Update Required", message=message, defaults={'is_read': False})
        elif user_profile.phone_number is None or not user_profile.phone_number:
            message = "Please update your profile with phone number"
            Notification.objects.update_or_create(user=request.user, title="Profile Update Required", message=message, defaults={'is_read': False})
        elif not user_profile.profile_pic:
            message = "Please update your profile with profile picture."
            Notification.objects.update_or_create(user=request.user, title="Profile Update Required", message=message, defaults={'is_read': False})
        else:
            Notification.objects.filter(
                    user=request.user, title="Profile Update Required"
                ).update(is_read=True)
            
    for summary in product_summaries:
        if request.user.is_authenticated:
            in_wishlist = is_in_wishlist(request,summary)
        else:
            in_wishlist=False
        book_data = {
            'product_summaries': summary,
            'in_wishlist': in_wishlist,
        }
        list1.append(book_data)  
    if request.user.is_superuser:            
        return redirect('admin_index') 
    elif request.user.is_staff:          
        return redirect('seller_index')
    else:
        return render(request, 'index.html',{'product_summaries':list1})

def loggout(request):
    print('Logged Out')
    logout(request)
    if 'username' in request.session:
        del request.session['username']
        request.session.clear()
    return redirect('index')

def seller_loggout(request):
    print('Logged Out')
    logout(request)
    if 'username' in request.session:
        del request.session['username']
        request.session.clear()
    return redirect(loginu)


def admin_loggout(request):
    print('Logged Out')
    logout(request)
    if 'username' in request.session:
        del request.session['username']
        request.session.clear()
    return redirect(loginu)


@login_required
def profile(request):
    user_profile = UserProfile.objects.get(user=request.user)

    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        profile_pic = request.FILES.get('profile_pic')
        phone_number = request.POST.get('phone_number')
        address = request.POST.get('address')
        reset_password = request.POST.get('reset_password')
        old_password = request.POST.get('old_password') 

        if 'profile_pic' in request.FILES:
            profile_pic = request.FILES['profile_pic']
            user_profile.profile_pic = profile_pic
            print('got')
        user_profile.name = name
        user_profile.phone_number = phone_number
        user_profile.address = address
        request.user.email = email

        # Check if all three password fields are not empty
        if old_password and reset_password and request.POST.get('cpass') == reset_password:
            if request.user.check_password(old_password):
                # The old password is correct, set the new password
                request.user.set_password(reset_password)
                request.user.save()
                update_session_auth_hash(request, request.user)  # Update the session to prevent logging out
            else:
                messages.error(request, "Incorrect old password. Password not updated.")
        else:
            print("Please fill all three password fields correctly.")
        
        user_profile.reset_password = reset_password
        user_profile.save()
        request.user.save()
        return redirect('profile') 

    context = {
        'user_profile': user_profile
    }
    return render(request, 'usertems/user_profile.html', context)

@login_required
def sellerprofile(request):
    user_profile = UserProfile.objects.get(user=request.user)
    seller = Seller.objects.get(user=request.user)
    existing_certification = Certification.objects.filter(user=request.user).first()
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        profile_pic = request.FILES.get('profile_pic')
        phone_number = request.POST.get('phone_number')
        address = request.POST.get('address')
        reset_password = request.POST.get('reset_password')
        old_password = request.POST.get('old_password') 

        if 'profile_pic' in request.FILES:
            profile_pic = request.FILES['profile_pic']
            user_profile.profile_pic = profile_pic
            print('got')
        user_profile.name = name
        seller.name = name
        user_profile.phone_number = phone_number
        seller.contact = phone_number
        user_profile.address = address
        seller.address=address
        request.user.email = email

        # Check if all three password fields are not empty
        if old_password and reset_password and request.POST.get('cpass') == reset_password:
            if request.user.check_password(old_password):
                # The old password is correct, set the new password
                request.user.set_password(reset_password)
                request.user.save()
                update_session_auth_hash(request, request.user)  # Update the session to prevent logging out
            else:
                messages.error(request, "Incorrect old password. Password not updated.")
        else:
            print("Please fill all three password fields correctly.")
        
        user_profile.reset_password = reset_password
        user_profile.save()
        request.user.save()
        seller.save()
        return redirect('sellerprofile') 

    context = {
        'user_profile': user_profile,
        'existing_certification':existing_certification
    }
    return render(request, 'seller/seller_profile.html', context)

@login_required
def user_dashboard(request):
    return render(request,'userprofile/user_dashboard.html')



def saveproduct(request):
    return render(request,'usertems/save.html')

def seller_register(request):
    if request.method == 'POST':
        name = request.POST.get('username')
        username = request.POST['email']
        email = request.POST['email']
        landmark = request.POST['landmark']
        password = request.POST['pwd']
        Cpassword = request.POST.get('cpwd')
        
        # Validate password strength
        try:
            password_validation.validate_password(password, User)
        except ValidationError as e:
            for error in e.error_list:
                messages.error(request, error)
            return redirect('seller_register')
        
        if password == Cpassword:
            if User.objects.filter(username=username).exists():
                messages.info(request, "Email already registered")
                return redirect('seller_register')
            else:
                user = User.objects.create_user(username=username, email=email, password=password)             
                contact = request.POST['contact']
                address = request.POST['address']
                landmark = request.POST['landmark']
                storename = request.POST['storename']
                seller = Seller.objects.create(user=user,email=email ,name=name, landmark=landmark, storename=storename, contact=contact, address=address)
                seller.save()
                # user_profile = UserProfile(user=user, email=email ,name=name)
                # user_profile.save()
               
                # Set the user as staff
                user.is_staff = True
                user.save()
                user_profile = UserProfile(user=user, email=email ,name=name)
                user_profile.save()
                
                # messages.success(request,"Seller request submitted. Please wait for approval.")
                # UserProfile.objects.create(user=user, name=name)
                subject = 'Welcome to Budora'
                message = 'We are thrilled to welcome you to Budora! Your account registration has been completed successfully, and you are now a valued member of our community.'
                from_email = settings.EMAIL_HOST_USER  # Your sender email address
                recipient_list = [seller.email]

                send_mail(subject, message, from_email, recipient_list)
                return redirect('loginu')
        else:
            messages.info(request, "Passwords do not match")
            return redirect('seller_register')
    return render(request, 'seller/seller_register.html')
                
def seller_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            auth_login(request, user)
            # Redirect to the seller's dashboard
            return redirect('seller_dashboard')
        else:
            # Handle authentication error
            return render(request, 'seller/seller_login.html', {'error_message': 'Invalid login credentials'})
    return render(request, 'seller/seller_login.html')

# def seller_index(request):
#     return render(request,'seller/base.html')


@login_required
def approvalpending(request):
    return render(request,'seller/approvalpending.html')




@login_required
def seller_index(request):
    if request.user.is_authenticated:
        user_profile = UserProfile.objects.get(user=request.user)
        if not user_profile.address and  not user_profile.phone_number and not user_profile.profile_pic:
            message = "Please update your profile with address, phone number, and profile picture."
            Notification.objects.update_or_create(user=request.user, title="Profile Update Required", message=message, defaults={'is_read': False})
        elif not user_profile.address and not user_profile.phone_number:
            message = "Please update your profile with address and phone number"
            Notification.objects.update_or_create(user=request.user, title="Profile Update Required", message=message, defaults={'is_read': False})
        elif not user_profile.profile_pic and not user_profile.phone_number:
            message = "Please update your profile with profile pic and phone number"
            Notification.objects.update_or_create(user=request.user, title="Profile Update Required", message=message, defaults={'is_read': False})
        elif not user_profile.profile_pic and not user_profile.address:
            message = "Please update your profile with address and profile pic"
            Notification.objects.update_or_create(user=request.user, title="Profile Update Required", message=message, defaults={'is_read': False})
        elif not user_profile.address:
            message = "Please update your profile with address."
            Notification.objects.update_or_create(user=request.user, title="Profile Update Required", message=message, defaults={'is_read': False})
        elif not user_profile.phone_number:
            message = "Please update your profile with phone number"
            Notification.objects.update_or_create(user=request.user, title="Profile Update Required", message=message, defaults={'is_read': False})
        elif not user_profile.profile_pic:
            message = "Please update your profile with profile picture."
            Notification.objects.update_or_create(user=request.user, title="Profile Update Required", message=message, defaults={'is_read': False})
        else:
            Notification.objects.filter(
                    user=request.user, title="Profile Update Required"
                ).update(is_read=True)
    selleruser = Seller.objects.get(user=request.user)
    orderitem_count = OrderItem.objects.filter(seller=selleruser).count()
    orderitem_reserve_count = OrderItem.objects.filter(seller=selleruser,seller_is_approved='APPROVED',customer_is_approved='collected',delivery_choice='reserve').count()
    orderitem_pending_count = OrderItem.objects.filter(seller=selleruser,seller_is_approved='PENDING',customer_is_approved='notcollected',delivery_choice='reserve').count()
    reserve_count = OrderItem.objects.filter(seller=selleruser,delivery_choice='reserve').count()
    order_count = OrderItem.objects.filter(seller=selleruser,delivery_choice='order').count()
    order_delivered_count = OrderItem.objects.filter(seller=selleruser,agent_is_approved='DELIVERED').count()
    order_notdelivered_count = OrderItem.objects.filter(seller=selleruser,agent_is_approved='notdelivered').count()
    product_count = Product.objects.filter(seller=selleruser).count()
    allreviews = Review.objects.filter(seller=request.user.seller)    
    avg_rating = allreviews.aggregate(Avg('rating'))['rating__avg'] or 0
    
    existing_certification = Certification.objects.filter(user=request.user).first()


    if existing_certification.expiry_date_to and existing_certification.expiry_date_to < timezone.now().date():
        existing_certification.is_approved = Certification.REJECTED  # Set it to 'rejected'
        existing_certification.save()

    if existing_certification:
        return render(request, 'seller/dashseller.html', {'existing_certification': existing_certification, 'allreviews':allreviews,'avg_rating':avg_rating,
        'orderitem_count':orderitem_count,
        'orderitem_reserve_count':orderitem_reserve_count,
        'orderitem_pending_count':orderitem_pending_count,
        'reserve_count':reserve_count,
        'order_delivered_count':order_delivered_count,
        'order_notdelivered_count':order_notdelivered_count,
        'product_count':product_count,
        'order_count':order_count,})

    if request.method == 'POST':
        # Handle form submission
        certification_image = request.FILES.get('certification_image')
        owner_name = request.POST.get('owner_name')
        store_name = request.POST.get('store_name')
        expiry_date_from = request.POST.get('expiry_date_from')
        expiry_date_to = request.POST.get('expiry_date_to')
        opening_time = request.POST.get('opening_time')
        closing_time = request.POST.get('closing_time')
        opening_days = request.POST.getlist('opening_days')  # Get a list of selected opening days
        store_image = request.FILES.get('store_image') 
        latitude = request.POST.get('latitude')
        longitude = request.POST.get('longitude')

        # Perform client-side validation here using JavaScript if needed

        # Perform server-side validation if needed
        # if not certification_image or not owner_name or not store_name or not expiry_date_from or not expiry_date_to:
        #     messages.error(request, 'Please fill in all required fields.')
        # else:
            # Create and save the Certification instance
        certification = Certification(
            user=request.user,
            certification_image=certification_image,
            owner_name=owner_name,
            store_name=store_name,
            expiry_date_from=expiry_date_from,
            expiry_date_to=expiry_date_to,
            opening_time=opening_time,
            closing_time=closing_time,
            opening_days=','.join(opening_days),  # Save selected days as a comma-separated string
            store_image=store_image,
            latitude=latitude,
            longitude=longitude,
        )
        certification.save()

        seller = Seller.objects.get_or_create(user=request.user)[0]  # Get or create Seller instance for the user
        seller.name = owner_name
        seller.email = request.user.email
        seller.storename = store_name
        seller.opening_time = opening_time
        seller.closing_time = closing_time
        seller.latitude = latitude
        seller.longitude = longitude
        seller.opening_days = ','.join(opening_days)  # Save selected days as a comma-separated string
        seller.save()

        subject = 'Your Certification Request Has Been Submitted'
        message = ' your certification request has been successfully received by our team. Your dedication to contributing to our community of plant enthusiasts is greatly appreciated. Our team will now begin the verification process, ensuring that all details are accurate and complete. Once this step is completed, you will be granted access to add your plants to our platform. Thank you for choosing our platform to share your love for plants. We are excited to have you as part of our community and look forward to seeing your contributions flourish.'
        from_email = settings.EMAIL_HOST_USER  # Your sender email address
        recipient_list = [seller.email]
        send_mail(subject, message, from_email, recipient_list) 

        superuser = User.objects.filter(is_superuser=True).first()
        message = "You have a new seller certification request"
        Notification.objects.update_or_create(
            user=superuser, title="New Certification Request", message=message, defaults={'is_read': False}
        )      
        return redirect('successseller')  # Redirect to a success page

    return render(request, 'seller/dashseller.html', {
        'existing_certification': existing_certification,
        'allreviews':allreviews,
        'avg_rating':avg_rating,
        'orderitem_count':orderitem_count,
        'orderitem_reserve_count':orderitem_reserve_count,
        'orderitem_pending_count':orderitem_pending_count,
        'reserve_count':reserve_count,
        'order_count':order_count,
    })

@login_required
def successseller(request):
    return render(request, 'seller/successseller.html')

@login_required
def successaddcategory(request):
    return render(request, 'admin/successaddcategory.html')

@login_required
def successaddproduct(request):
    return render(request, 'seller/successaddproduct.html')

@login_required
def viewcategory(request):
    categories = Category.objects.all()
    return render(request, 'admin/viewcategory.html', {'categories': categories})

@login_required
def viewaddproduct(request):
    existing_certification = Certification.objects.filter(user=request.user).first()

    if not existing_certification:
        return redirect('seller_index')

    try:
        seller = request.user.seller  # Assuming the Seller profile is associated with the User model
        user_products = Product.objects.filter(seller=seller)
    except Seller.DoesNotExist:
        user_products = []

    return render(request, 'seller/viewaddproduct.html', {'user_products': user_products})
 
@login_required
def viewproducts(request):
    # Retrieve all products
    all_products = Product.objects.all()

    context = {
        'all_products': all_products,
    }
    return render(request, 'admin/viewproducts.html', context)



@login_required
def addproducts(request):
    
    existing_certification = Certification.objects.filter(user=request.user).first()

    if existing_certification:
        certification_status = existing_certification.is_approved
    else:
        certification_status = 'pending'  # Set a default value if no certification exists

    if certification_status == 'approved':
        if request.method == 'POST':
        # Extract data from the POST request
            product_name = request.POST.get('product_name')
            formatted_product_name = product_name.capitalize()
            select_category_id = request.POST.get('select_category')
            product_price = request.POST.get('product_price')
            product_stock = request.POST.get('product_stock')
            product_image = request.FILES.get('product_image')

        # Retrieve the selected category
            category = Category.objects.get(id=select_category_id)

        # Check if a product with the same name already exists in the selected category
        # Check if the current user has already added a product with the same name in this category
            existing_product = Product.objects.filter(
                product_name=formatted_product_name,
                category=category,
                seller__user=request.user # Filter by the current user
            )

            if existing_product.exists():
                error_message = "You have already added a product with this name in the selected category."
                return render(request, 'seller/addproducts.html', {'error_message': error_message})

        # Retrieve the seller associated with the currently logged-in user
            seller = Seller.objects.get(user=request.user)
        # Create and save the Product instance
            product = Product(
                product_name=product_name,
                category=category,
                product_price=product_price,
                product_stock=product_stock,
                product_image=product_image,
                seller=seller  # Associate the seller with the product

            )
            product.save()
            superuser = User.objects.filter(is_superuser=True).first()
           
            message = f"A new product has been added by '{seller.storename}'"
            Notification.objects.update_or_create(
                user=superuser, title="New Product", message=message, defaults={'is_read': False}
            )      
            return redirect('successaddproduct')  # Redirect to a success page after saving the product

        categories = Category.objects.all()  # Retrieve all Category objects from the database

        context = {
            'categories': categories,
            'certification_status': certification_status,
          # Pass the categories queryset to the template context
            }
        
        return render(request, 'seller/addproducts.html', context)
    else:
        return render(request, 'seller/addproducts.html', {'certification_status': certification_status})

@login_required
def delete_product(request, product_id):
    try:
        product = Product.objects.get(id=product_id)
        product.delete()
    except Product.DoesNotExist:
        # Handle the case where the product with the given ID does not exist.
        pass

    # Redirect back to the viewproducts page or wherever you want to go after deletion.
    return redirect('viewproducts')

@login_required
def dashlegal(request):
    # Retrieve Certification objects including their IDs
    seller_applications = Certification.objects.all()
    today = timezone.now().date()

    for certification in seller_applications:
        if certification.expiry_date_to and certification.expiry_date_to < timezone.now().date():
            certification.is_approved = Certification.REJECTED  # Set it to 'rejected'
            certification.save()

      
    # Retrieve User roles for each Certification applicant
    user_roles = {}
    for application in seller_applications:
        # Ensure the user associated with the Certification exists
        user = get_object_or_404(User, id=application.user_id)

        # Retrieve user roles
        user_roles[application.id] = {
            'is_admin': user.is_superuser,
            'is_customer': user,
            'is_seller': user.is_staff
        }

    context = {
        'seller_applications': seller_applications,
        'user_roles': user_roles,  # Include user roles in the context
        'today': today,
    }
    return render(request, 'admin/dashlegal.html', context)



@login_required
def addcategory(request):
    form_error_message = None  # Initialize form_error_message as None

    if request.method == 'POST':
        try:
            # Retrieve form data directly from the request
            category_name = request.POST.get('category_name')
            formatted_category_name = category_name.title()  # Use title() to capitalize all words
            category_description = request.POST.get('category_description')

            # Check if the category with the given name already exists
            existing_category = Category.objects.filter(category_name=formatted_category_name).first()

            if existing_category:
                # The category already exists
                form_error_message = 'Category already exists.'
            else:
                # Create a new Category instance with the form data
                category = Category(category_name=formatted_category_name, category_description=category_description)
                category.save()
                messages.success(request, 'Category created successfully.')
                sellers=Seller.objects.all()
                for seller in sellers:
                    message = "A new category has been added."
                    Notification.objects.update_or_create(
                        user=seller.user, title="New Category Added", message=message, defaults={'is_read': False}
                    )
                return redirect('successaddcategory')

        except IntegrityError as e:
            # Handle database integrity error (e.g., unique constraint violation)
            form_error_message = 'Error creating category: {}'.format(str(e))

    return render(request, 'admin/addcategory.html', {'form_error_message': form_error_message})





@login_required
def delete_category(request, category_id):
    # Get the category object to delete
    category = get_object_or_404(Category, pk=category_id)

    associated_products = Product.objects.filter(category=category)

    if request.method == 'POST':
        # Delete all associated products
        associated_products.delete()
        
        # Delete the category
        category.delete()
        
        sellers=Seller.objects.all()
        for seller in sellers:
            message = f"The category '{category.category_name}' has been deleted."
            Notification.objects.update_or_create(
                user=seller.user, title="Category Deleted", message=message, defaults={'is_read': False}
            )
        return redirect('viewcategory')  # Redirect to the category list page

    return render(request, 'admin/delete_category.html', {'category': category, 'associated_products': associated_products})

@login_required
def edit_category(request, category_id):
    category = get_object_or_404(Category, id=category_id)
    editcategory_error_message = None  # Initialize form_error_message as None

    if request.method == 'POST':
        new_category_name = request.POST['category_name']
        # Check if a category with the same name already exists
        if Category.objects.filter(category_name=new_category_name).exclude(id=category.id).exists():
            editcategory_error_message = 'Category with this name already exists.'
        else:
            # Update the category if no duplicate name found
            category.category_name = request.POST['category_name']
            category.category_description = request.POST['category_description']
            category.save()
            return redirect('viewcategory')  # Replace 'category_list' with your category list URL name

    return render(request, 'admin/edit_category.html', {'category': category, 'editcategory_error_message': editcategory_error_message})

@login_required
def seller_approve_order(request, order_id):
    order = get_object_or_404(OrderItem, id=order_id)
    if request.method == 'POST':
        order.seller_is_approved = OrderItem.APPROVED  # Set it to 'approved'
        order.save()
        # subject = 'Congratulations! Your License Has Been Approved'
        # message = 'We are delighted to inform you that your license application has been successfully approved. Your dedication and compliance with the necessary requirements have made this approval possible. We appreciate your patience throughout the process. With your approved license, you are now officially recognized and authorized to add your plants. '
        # from_email = settings.EMAIL_HOST_USER  # Your sender email address
        # recipient_list = [order.seller.email]
        # send_mail(subject, message, from_email, recipient_list)
    return redirect('sellerorder')
    
@login_required
def approve_certification(request, certification_id):
    certification = get_object_or_404(Certification, id=certification_id)
    if request.method == 'POST':
        certification.is_approved = Certification.APPROVED  # Set it to 'approved'
        certification.save()
        subject = 'Congratulations! Your License Has Been Approved'
        message = 'We are delighted to inform you that your license application has been successfully approved. Your dedication and compliance with the necessary requirements have made this approval possible. We appreciate your patience throughout the process. With your approved license, you are now officially recognized and authorized to add your plants. '
        from_email = settings.EMAIL_HOST_USER  # Your sender email address
        recipient_list = [certification.user.email]
        send_mail(subject, message, from_email, recipient_list)
    return redirect('dashlegal')
    

@login_required
def reject_certification(request, certification_id):
    certification = get_object_or_404(Certification, id=certification_id)
    if request.method == 'POST':
        certification.is_approved = Certification.REJECTED  # Set it to 'rejected'
        certification.save()
        subject = 'Important Notice: Your License Application Has Been Declined'
        message = 'We regret to inform you that your recent license application has been declined, and as a result, you will not be able to add your plants on our platform. '
        from_email = settings.EMAIL_HOST_USER  # Your sender email address
        recipient_list = [certification.user.email]
        send_mail(subject, message, from_email, recipient_list)
    return redirect('dashlegal')

@login_required
def user_list(request):
    users = User.objects.all()
    return render(request, 'admin/userlist.html', {'users': users})

@login_required
def activate_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    if request.method == 'POST':
        user.is_active = True
        user.save()
        subject = 'Important Notice: Your Account Is Now Active'
        message = 'We are pleased to inform you that your account has been successfully activated. Welcome to our platform! Your account is now ready for you to explore and enjoy all the features and benefits it offers. Whether you are here for information, services, or interactions, we are excited to have you as part of our community.'
        from_email = settings.EMAIL_HOST_USER  # Your sender email address
        recipient_list = [user.email]
        send_mail(subject, message, from_email, recipient_list)
    return redirect('user_list')

@login_required
def deactivate_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    if request.method == 'POST':
        user.is_active = False
        user.save()
        subject = 'Important Notice: Account Deactivation'
        message = 'We regret to inform you that your user account has been deactivated. This action has been taken based on certain circumstances or violations of our policies that have come to our attention.As a result, you will no longer have access to your account and its associated services. If you believe this deactivation is in error or have any questions regarding this decision, please contact our support team by replying to this mail.'
        from_email = settings.EMAIL_HOST_USER  # Your sender email address
        recipient_list = [user.email]
        send_mail(subject, message, from_email, recipient_list)
    return redirect('user_list')

from django.views.decorators.csrf import csrf_exempt
@csrf_exempt  # Use csrf_exempt for simplicity; consider using a csrf token for security in production
def delete_user(request, user_id):
    # Check if the request method is POST (for safety, you might want to use a confirmation modal before sending the request)
    if request.method == 'POST':
        # Get the user object to delete
        user = get_object_or_404(User, id=user_id)

        # Check if the user can be deleted (e.g., you might want to add custom logic here)
        if not user.is_superuser:
            user.delete()
            return JsonResponse({'message': 'User deleted successfully.'})

    return JsonResponse({'error': 'Unable to delete user.'}, status=400)

@login_required
def edit_user(request, user_id):
    user = get_object_or_404(User, id=user_id)

    if request.method == 'POST':
        # Handle form submission and update user details
        user.username = request.POST['username']
        user.email = request.POST['email']

        # Update user role based on the selected role option
        role = request.POST.get('role')
        if role == 'customer':
            user.is_staff = False
            user.is_superuser = False
        elif role == 'staff':
            user.is_staff = True
            user.is_superuser = False
        elif role == 'superuser':
            user.is_staff = True
            user.is_superuser = True

        user.save()
        return redirect('user_list')  # Redirect back to the user list page

    return render(request, 'admin/edituser.html', {'user': user})

@login_required 
def view_products(request):
    product_summaries = ProductSummary.objects.all()
    return render(request, 'admin/viewstock.html', {'product_summaries': product_summaries})

@login_required
def stock_approve(request, product_summary_id):
    order = get_object_or_404(ProductSummary, id=product_summary_id)
    if request.method == 'POST':
        order.stock_is_approved = ProductSummary.APPROVED  # Set it to 'approved'
        order.save()
    return redirect('viewstock')

@login_required 
def edit_product_stock(request, pk):
    product_summary = get_object_or_404(ProductSummary, pk=pk)

    if request.method == 'POST':
        product_summary.product_sci_name = request.POST['product_sci_name']
        product_summary.product_description = request.POST['product_description']
        product_summary.product_image = request.FILES.get('product_image')
        product_summary.light_requirements = request.POST['light_requirements']
        product_summary.water_requirements = request.POST['water_requirements']
        product_summary.humidity_requirements = request.POST['humidity_requirements']
        product_summary.soil_type = request.POST['soil_type']
        product_summary.toxicity_information = request.POST['toxicity_information']
        product_summary.maintenance_instructions = request.POST['maintenance_instructions']
        
        # Get the corresponding Product object based on product_name
        product = Product.objects.get(product_name=product_summary.product_name)
        product_summary.product = product
        product_summary.category = product.category
        
        product_summary.save()
        return redirect('viewstock')

    return render(request, 'admin/editstock.html', {'product_summary': product_summary})


@login_required 
def edit_product(request, product_id):
    product = get_object_or_404(Product, id=product_id)
    # categories = Category.objects.all()  # Assuming you have a 'Category' model

    if request.method == 'POST':
        # Update the product fields based on form input
        product.product_name = request.POST['product_name']
        
        # Get the category instance based on the selected ID
        # category_id = request.POST.get('select_category')
        # if category_id:
        #     category = get_object_or_404(Category, id=category_id)
        #     product.category = category
        
        product.product_price = request.POST['product_price']
        product.product_stock = request.POST['product_stock']
        
        # Handle product image upload or update
        # if 'product_image' in request.FILES:
        #     product.product_image = request.FILES['product_image']

        # Save the updated product
        product.save()
        return redirect('viewaddproduct')  # Redirect to the product list page

    return render(request, 'seller/edit_product.html', {'product': product})

@login_required
def delete_add_product(request, product_id):
    product = get_object_or_404(Product, id=product_id)

    if request.method == 'POST':
        # Handle form submission for deleting the product
        product.delete()
        return redirect('viewaddproduct')  # Redirect to the product list page

    return render(request, 'seller/delete_add_product.html', {'product': product})


@login_required
def store(request): 
    product_summaries = ProductSummary.objects.all() 
    list1=[]
    for summary in product_summaries:
        if request.user.is_authenticated:
            in_wishlist = is_in_wishlist(request,summary)
        else:
            in_wishlist=False
        book_data = {
                'product_summaries': summary,
                'in_wishlist': in_wishlist,
            }
        list1.append(book_data)  
    return render(request, 'usertems/store.html', {'product_summaries':list1})


def is_in_wishlist(request,summary):
    user = request.user
    is_in_wishlist=Wishlist.objects.filter(user=user, product=summary).first()
    if is_in_wishlist:
        return True
    else:
        False

def storewishlist(request):
    product_summaries = ProductSummary.objects.all()   
    return render(request, 'usertems/store.html', {'product_summaries': product_summaries})

@login_required
def product_single(request, product_id):
    product = get_object_or_404(ProductSummary, pk=product_id)
    product_name = product.product.product_name
    products=Product.objects.filter(product_name=product_name)
    product_details=Product.objects.filter(product_name=product.product_name)

    sellers = []
    for i in products:
        sellers.append(i.seller)

    all_average_ratings = {}
    for seller in sellers:
        allreviews = Review.objects.filter(seller=seller)
        avg_rating = allreviews.aggregate(Avg('rating'))['rating__avg'] or 0
        all_average_ratings[seller] = avg_rating
        seller.avgrating = avg_rating
        seller.save()
    print(all_average_ratings)
    

    # print(f"sellers_with_product: {sellers_with_product}")
    user = request.user


    if request.user.is_authenticated:
    # Check if the product is already in the user's cart
        existing_wishlist_item = Wishlist.objects.filter(user=user, product=product).first()
        is_in_wishlist = existing_wishlist_item is not None

    else:
        is_in_wishlist=False
    if request.method == 'POST':
        image = product.product_image

    
        if not is_in_wishlist:
            # If the product is not in the cart, add it to the cart with the specified quantity
            Wishlist.objects.create(user=user, product=product, image=image)
            
        else:
            print("Already in Cart")

        return redirect('product_single',product_id=product_id)
    
    # print(sellers_with_product)
    return render(request, 'usertems/product.html', {'product': product,'is_in_wishlist': is_in_wishlist,'sellers_with_product':sellers,'product_details':product_details,
                                                     'allreviews':allreviews,'avg_rating':avg_rating
                                                     })

# def product_stores(request, product_id):
#     try:
#         product_summary = ProductSummary.objects.get(pk=product_id)
        
#         print(product_summary.product.seller.storename)
#     except ProductSummary.DoesNotExist:
#         # Handle the case where the specified product_summary_id does not exist.
#         # You can return an error response or render an appropriate template.
#         return HttpResponse("Product Summary not found", status=404)

#     # Query sellers related to products associated with this product summary
#     sellers_with_product = Seller.objects.filter(products__product_summary=product_summary)
#     print(f"product_id: {product_id}")
#     print(f"product_summary: {product_summary}")
#     print(f"sellers_with_product: {sellers_with_product}")


#     return render(request, 'usertems/product_stores.html', {'product_summary': product_summary, 'sellers_with_product': sellers_with_product})


@login_required
def wishlist_view(request):
    # Assuming you have user authentication and each user has a unique cart
    user = request.user

    # Retrieve the user's cart items
    wishlist_items = Wishlist.objects.filter(user=user)
    total_items = len(wishlist_items)

    context = {
        'wishlist_items': wishlist_items,
        'total_items': total_items
    }

    return render(request, 'usertems/wishlist.html', context)

def remove_all_from_wishlist(request):
    user = request.user
    # Get all wishlist items for the current user
    wishlist_items = Wishlist.objects.filter(user=user)

    # Delete all wishlist items
    wishlist_items.delete()

    return render(request, 'usertems/wishlist.html')

def remove_from_wishlist(request, wishlist_item_id):
    wishlist_item = get_object_or_404(Wishlist, id=wishlist_item_id)

    if request.method == 'POST':
        wishlist_item.delete()

    return redirect('wishlist')  

@login_required
def remove_productwishlist(request, product_id):
    product = get_object_or_404(ProductSummary, pk=product_id)

    wishlist_item = Wishlist.objects.filter(product=product)
    if request.method == 'POST':
        wishlist_item.delete()
    return redirect('product_single',product_id=product_id) 

def remove_storewishlist(request, wishlist_item_id):
    wishlist_item = get_object_or_404(Wishlist, id=wishlist_item_id)

    if request.method == 'POST':
        wishlist_item.delete()

    return redirect('store') 

def remove_indexwishlist(request, wishlist_item_id):
    wishlist_item = get_object_or_404(Wishlist, id=wishlist_item_id)

    if request.method == 'POST':
        wishlist_item.delete()

    return redirect('index.html') 

@login_required
def add_productwishlist(request, product_id):
    product = get_object_or_404(ProductSummary, pk=product_id)
    user = request.user

    # Check if the product is already in the user's cart
    existing_wishlist_item = Wishlist.objects.filter(user=user, product=product).first()
    is_in_wishlist = existing_wishlist_item is not None

    if request.method == 'POST':
        image = product.product_image

        if not is_in_wishlist:
            # If the product is not in the cart, add it to the cart with the specified quantity
            Wishlist.objects.create(user=user, product=product, image=image)
        else:
            print("Already in Cart")

        return redirect('product_single',product_id=product_id)
    return render(request, 'usertems/product.html', {'product': product,'is_in_wishlist': is_in_wishlist})

def add_storewishlist(request, product_id):
    product = get_object_or_404(ProductSummary, pk=product_id)
    user = request.user

    # Check if the product is already in the user's cart
    existing_wishlist_item = Wishlist.objects.filter(user=user, product=product).first()
    is_in_wishlist = existing_wishlist_item is not None

    if request.method == 'POST':
        image = product.product_image

        if not is_in_wishlist:
            # If the product is not in the cart, add it to the cart with the specified quantity
            Wishlist.objects.create(user=user, product=product, image=image)
        else:
            print("Already in Cart")

        return redirect('store')
    return render(request, 'usertems/store.html', {'product': product,'is_in_wishlist': is_in_wishlist})

@login_required
def add_indexwishlist(request, product_id):
    product = get_object_or_404(ProductSummary, pk=product_id)
    user = request.user

    # Check if the product is already in the user's cart
    existing_wishlist_item = Wishlist.objects.filter(user=user, product=product).first()
    is_in_wishlist = existing_wishlist_item is not None

    if request.method == 'POST':
        image = product.product_image

        if not is_in_wishlist:
            # If the product is not in the cart, add it to the cart with the specified quantity
            Wishlist.objects.create(user=user, product=product, image=image)
        else:
            print("Already in Cart")

        return redirect('index.html')
    return render(request, 'index.html', {'product': product,'is_in_wishlist': is_in_wishlist})

@login_required
def submit_review_productpage(request, seller_id, product_id):
    if request.method == 'POST':
        description = request.POST.get('description')
        rating = int(request.POST.get('rating', 0))
        review_id = request.POST.get('review_id')  # Get the review_id from the form

        seller = get_object_or_404(Seller, pk=seller_id)
        print(review_id)

        # Sentiment Analysis using TextBlob
        sentiment_score = analyze_sentiment(description)

        # Calculate the rating based on sentiment score
        star_rating = map_sentiment_to_rating(sentiment_score)

        if review_id:
            # If review_id is available, it's an edit action
            review = Review.objects.get(pk=review_id)
            review.rating = star_rating  # Update the rating based on sentiment
            review.description = description
            review.save()
        else:
            # It's an add action
            review = Review.objects.create(
                user=request.user,
                rating=star_rating,  # Use calculated rating
                description=description,
                seller=seller,
                review_status='REVIEWED',
            )
        userprofile=UserProfile.objects.filter(user=request.user)
        message = f" '{userprofile.name}' has reviewed your store"
        Notification.objects.create(
            user=seller.user, title="Review Added", message=message, is_read=False
        )
        send_review_notification_email(request.user, seller, review)

        # Redirect back to the product page or another appropriate page
        return redirect('seller_detail', seller_id=seller_id, product_id=product_id)

def send_review_notification_email(user, seller, review):
    # Email to the user
    user_subject = 'Review Submitted Successfully'
    user_message = f'Dear {user.userprofile.name},\n\n' \
                   'Thank you for submitting your review on our platform. ' \
                   'Your feedback is valuable to us.\n\n' \
                   'Best regards,\n' \
                   'The Budora Team'
    user_from_email = settings.EMAIL_HOST_USER
    user_recipient_list = [user.email]

    # Email to the seller
    seller_subject = 'New Review Posted for Your Product'
    seller_message = f'{seller.storename},\n\n' \
                     f'A new review has been posted for your product by {user.userprofile.name}. ' \
                     'You can log in to your seller account to view the review.\n\n' \
                     'Best regards,\n' \
                     'The Budora Team'
    seller_from_email = settings.EMAIL_HOST_USER
    seller_recipient_list = [seller.email]

    # Send emails
    send_mail(user_subject, user_message, user_from_email, user_recipient_list, fail_silently=False)
    send_mail(seller_subject, seller_message, seller_from_email, seller_recipient_list, fail_silently=False)
#cart
@login_required
def seller_detail(request, seller_id, product_id):
    
    seller = get_object_or_404(Seller, pk=seller_id)
    product = get_object_or_404(Product, pk=product_id)
    user_orders = Order.objects.filter(user=request.user)
    if user_orders:
        orders = OrderItem.objects.filter(seller=seller).first()
    else:
        orders = None
    print(orders)
    # user_orders = Order.objects.filter(user=request.user,seller=seller).first()
    review = Review.objects.filter(user=request.user, seller=seller).first()
    allreviews = Review.objects.filter(seller=seller)
    
    if review:
        review_status = review.review_status
        review_id = review.pk  # Add the review_id to the order
        review_desc=review.description
    else:
        review_status = 'Pending'  # Default to "Pending" if no review found
        review_id = None  # Set review_id to None if no review found
        review_desc = None
    user = request.user
   
    avg_rating = allreviews.aggregate(Avg('rating'))['rating__avg'] or 0

    # Check if the product is already in the user's cart
    existing_cart_item = Cart.objects.filter(user=user, product=product).first()
    is_in_cart = existing_cart_item is not None

    # Fetch all products related to this seller
    seller_products = seller.products.all()

    # Calculate the total stock from those products
    total_stock = sum(product.product_stock for product in seller_products)
    
    # Include the product stock and cart information in the context
    context = {
        'seller': seller,
        'total_stock': total_stock,
        'seller_products': seller_products,
        'product': product,
        'is_in_cart': is_in_cart,
        'review_status' : review_status,
        'review_id' : review_id,
        'avg_rating': avg_rating,
        'orders': orders,
        'review_desc':review_desc,
    }
    if len(allreviews)>0:
        context['allreviews']=allreviews
        print(len(allreviews))


    if request.method == 'POST':
        # If it's a POST request, get the quantity from the form
        quantity = int(request.POST.get('quantity', 1))  # Default to 1 if not provided
        image = product.product_image
        seller = product.seller

        if not is_in_cart:
            # If the product is not in the cart, add it to the cart with the specified quantity
            Cart.objects.create(user=user, product=product, quantity=quantity, image=image,seller=seller)
        else:
            # If the product is already in the cart, update the quantity
            existing_cart_item.quantity += quantity
            existing_cart_item.save()

        return redirect('cart')

    return render(request, 'usertems/storeproduct.html', context)

def load_reviews(request, seller_id):
    seller = get_object_or_404(Seller, pk=seller_id)
    reviews = Review.objects.filter(seller=seller)

    # You can format the reviews as needed before sending them to the template
    # For example, you can serialize them to JSON
    reviews_data = [{'user': review.user.username, 'comment': review.comment} for review in reviews]
    if len(reviews_data)>0:
    # Send the reviews data as JSON response
        return JsonResponse({'reviews': reviews_data})
    else:
        return JsonResponse()


@login_required
def cart_view(request):
    # Assuming you have user authentication and each user has a unique cart
    user = request.user

    # Retrieve the user's cart items
    cart_items = Cart.objects.filter(user=user)
   
    # Calculate the total price of items in the cart
    total_price = sum(cart_item.product.product_price * cart_item.quantity for cart_item in cart_items)

    context = {
        'cart_items': cart_items,
        'total_price': total_price,
    }

    return render(request, 'usertems/cart.html', context)

def remove_from_cart(request, cart_item_id):
    cart_item = get_object_or_404(Cart, id=cart_item_id)

    if request.method == 'POST':
        cart_item.delete()

    return redirect('cart')

def update_cart_item(request, cart_item_id):
    if request.method == 'POST':
        # Retrieve the cart item
        cart_item = Cart.objects.get(id=cart_item_id)

        # Get the new quantity from the form
        new_quantity = int(request.POST.get('quantity'))

        if new_quantity > 0 and new_quantity <= cart_item.product.product_stock:
            # Update the cart item's quantity if it's a valid value
            cart_item.quantity = new_quantity
            cart_item.save()
        else:
            # Display an error message if the quantity is invalid
            print('Not Enough Stock Available')

    # Redirect back to the cart view
    return redirect('cart')
     

from .models import BillingDetails, Cart, Order, OrderItem  # Import your models here
from django.shortcuts import render, redirect
from decimal import Decimal

from django.db import transaction

import requests

@login_required
@transaction.atomic
def checkout(request):
    total_price = 0  # Initialize total_price outside the if block
    cart_items = Cart.objects.filter(user=request.user)  # Define cart_items here
    billing_details = None  # Initialize billing_details to None

    # Check if billing details exist for the user
    if BillingDetails.objects.filter(user=request.user).exists():
        billing_details = BillingDetails.objects.get(user=request.user)

    if request.method == 'POST' and 'place_order' in request.POST:
        # If billing details already exist, you can skip processing the form and just calculate the total price
        if not billing_details:
            # Retrieve and process the form data for billing details
            first_name = request.POST.get('firstname')
            last_name = request.POST.get('lastname')
            state = request.POST.get('state')
            postcode_zip = request.POST.get('postcodezip')
            phone = request.POST.get('phone')
            email = request.POST.get('emailaddress')
            town = request.POST.get('towncity')
            streetaddress = request.POST.get('streetaddress')
           

            if request.POST.get('apartmentsuiteunit'):
                apartmentsuiteunit = request.POST.get('apartmentsuiteunit')

            else:
                apartmentsuiteunit = None
            # Check if latitude and longitude are provided in the form
            latitude = request.POST.get('latitude')
            longitude = request.POST.get('longitude')

            if latitude and longitude:
                # Use latitude and longitude from the form
                latitude = float(latitude)
                longitude = float(longitude)
            else:
                # Use geocoding service to get latitude and longitude
                address = f"{state}, {postcode_zip}"
                geocode_url = f"https://nominatim.openstreetmap.org/search?q={address}&format=json"
                response = requests.get(geocode_url)
                if response.ok:
                    data = response.json()
                    if data:
                        latitude = float(data[0]['lat'])
                        longitude = float(data[0]['lon'])
                    else:
                        latitude = None
                        longitude = None
                else:
                    latitude = None
                    longitude = None

            print(latitude)
            print(longitude)
            # Create BillingDetails object (assuming BillingDetails is a separate model)
            billing_details = BillingDetails(
                user=request.user,
                first_name=first_name,
                last_name=last_name,
                state=state,
                postcode_zip=postcode_zip,
                phone=phone,
                email=email,
                latitude=latitude,  # Save latitude
                longitude=longitude,  # Save longitude
                town_city=town,
                street_address=streetaddress,
                apartment_suite_unit=apartmentsuiteunit,
            )
            billing_details.save()

        total_price = sum(item.product.product_price * item.quantity for item in cart_items)

        # Convert total_price to a float before storing it in the session
        request.session['order_total'] = float(total_price)

        # Redirect to the payment page to complete the order
        return redirect('payment')

    # If it's not a POST request or not a place order request, continue displaying the cart items
    total_price = sum(item.product.product_price * item.quantity for item in cart_items)

    # Convert total_price to a float before passing it to the template
    context = {
        'cart_items': cart_items,
        'total_price': float(total_price),
        'billing_details': billing_details,  # Pass billing_details to the template
    }

    return render(request, 'usertems/checkout.html', context)



def save_location_view(request):
    if request.method == 'POST':
        latitude = request.POST.get('latitude')
        longitude = request.POST.get('longitude')

        # Get the billing details object for the user if it exists; otherwise, create a new one
        billingdetails, created = BillingDetails.objects.get_or_create(user=request.user)

        # Update latitude and longitude
        if hasattr(billingdetails, 'latitude') and hasattr(billingdetails, 'longitude'):
            billingdetails.latitude = latitude
            billingdetails.longitude = longitude
            billingdetails.save()
            return JsonResponse({'message': 'Location saved successfully.'})
        else:
            return JsonResponse({'error': 'BillingDetails object does not have latitude and longitude attributes.'}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request.'}, status=400)

#payment
from django.shortcuts import render
import razorpay
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponseBadRequest

razorpay_client = razorpay.Client(
    auth=(settings.RAZOR_KEY_ID, settings.RAZOR_KEY_SECRET))

@login_required
def payment(request):
    cart_items = Cart.objects.filter(user=request.user)
    billingdetails = BillingDetails.objects.get(user=request.user)
    agents = DeliveryAgent.objects.all()
    latitude = billingdetails.latitude
    longitude = billingdetails.longitude

    for agent in agents:
        if latitude is not None and longitude is not None:
            # Calculate distance for each seller using haversine
            distance = haversine(agent.latitude, agent.longitude, billingdetails.latitude, billingdetails.longitude)
            UserAgentDistance.objects.update_or_create(
                user=request.user,
                agent=agent,
                defaults={'distance': distance}
            )
    useragent = UserAgentDistance.objects.filter(user=request.user)
    nearby_agent = useragent.filter(
        distance__isnull=False,
        user=request.user,
        agent__availability='available'
    ).order_by('distance')[:1]
    
    if nearby_agent:
        total_price = Decimal(sum(cart_item.product.product_price * cart_item.quantity for cart_item in cart_items))
        currency = 'INR'
        payment_error_message = None
        amount = int(total_price * 100)
        
        # Create a Razorpay Order
        razorpay_order = razorpay_client.order.create(dict(
            amount=amount,
            currency=currency,
            payment_capture='0'
        ))

        # Order id of the newly created order
        razorpay_order_id = razorpay_order['id']
        callback_url = '/paymenthandler/'

        # Create an Order outside the loop
        order = Order.objects.create(
            user=request.user,
            total_price=total_price,
            razorpay_order_id=razorpay_order_id,
            payment_status=Order.PaymentStatusChoices.PENDING,
        )
        
    


    # for agent in agents:
    #    if (agent.availability == 'available' and 
    #         (timezone.now() - agent.assigned_timestamp).total_seconds() >= 12 * 60 * 60): 
    #         agent.availability = 'not_available'
    #         agent.save()




    # statusmessage = "Your availability status has been marked to unavailable"
    # Notification.objects.create(
    #         user=nearest_delivery_agent.user, title="Status Change", message=statusmessage, is_read=False
    #     )
    
    
        nearest_user_agent_distance = nearby_agent.first()
        if nearest_user_agent_distance:
            nearest_delivery_agent = nearest_user_agent_distance.agent


            
            # nearest_delivery_agent.assigned_timestamp = timezone.now()



        # Loop through cart items and create OrderItem for each product
        for cart_item in cart_items:
            product = cart_item.product
            price = product.product_price
            quantity = cart_item.quantity
            total_item_price = price * quantity

            message = f"A new order for  '{cart_item.product.product_name}' has been placed."
            Notification.objects.create(
                user=cart_item.product.seller.user, title="New Order", message=message, is_read=False
            )
            Notification.objects.create(
                user=nearest_delivery_agent.user, title="New Order", message=message, is_read=False
            )
        
            order_item = OrderItem.objects.create(
                order=order,
                product=product,
                seller=product.seller,
                quantity=quantity,
                price=price,
                total_price=total_item_price,
                deliveryagent=nearest_delivery_agent,
                delivery_choice='order'
            )

        # Save the order to generate an order ID
        order.save()
        Assigndeliveryagent.objects.create(
                seller=cart_item.product.seller, user=request.user, billingdetails=billingdetails, order=order, deliveryagent=nearest_delivery_agent
            )
        nearest_delivery_agent.availability = 'not_available'
        
        nearest_delivery_agent.save()
        agent_available = 'available' 
        # Create a context dictionary with all the variables you want to pass to the template
        context = {
            'cart_items': cart_items,
            'total_price': total_price,
            'razorpay_order_id': razorpay_order_id,
            'razorpay_merchant_key': settings.RAZOR_KEY_ID,
            'razorpay_amount': amount,
            'currency': currency,
            'callback_url': callback_url,
            'order_item': order_item,
            'agent_available':agent_available
        }
    else:
        payment_error_message = "No delivery agents available at this time, try again later"
        agent_available = 'unavailable'
        context = {
            'payment_error_message': payment_error_message,
            'agent_available':agent_available
        }
    return render(request, 'usertems/payment.html', context=context)




@csrf_exempt
def paymenthandler(request):
    if request.method == "POST":
        payment_id = request.POST.get('razorpay_payment_id', '')
        razorpay_order_id = request.POST.get('razorpay_order_id', '')
        signature = request.POST.get('razorpay_signature', '')

        # Verify the payment signature.
        params_dict = {
            'razorpay_order_id': razorpay_order_id,
            'razorpay_payment_id': payment_id,
            'razorpay_signature': signature
        }
        result = razorpay_client.utility.verify_payment_signature(params_dict)

        if not result:
            # Signature verification failed.
            return render(request, 'paymentfail.html')

        # Signature verification succeeded.
        # Retrieve the order from the database
        try:
            order = Order.objects.get(razorpay_order_id=razorpay_order_id)
        except Order.DoesNotExist:
            return HttpResponseBadRequest("Order not found")

        if order.payment_status == Order.PaymentStatusChoices.SUCCESSFUL:
            # Payment is already marked as successful, ignore this request.
            return HttpResponse("Payment is already successful")

        if order.payment_status != Order.PaymentStatusChoices.PENDING:
            # Order is not in a pending state, do not proceed with stock update.
            return HttpResponseBadRequest("Invalid order status")

        # Capture the payment amount
        amount = int(order.total_price * 100)  # Convert Decimal to paise
        razorpay_client.payment.capture(payment_id, amount)

        # Update the order with payment ID and change status to "Successful"
        order.payment_id = payment_id
        order.payment_status = Order.PaymentStatusChoices.SUCCESSFUL
        order.save()

        # Remove the products from the cart and update stock
        cart_items = Cart.objects.filter(user=request.user)
        for cart_item in cart_items:
            product = cart_item.product
            if product.product_stock >= cart_item.quantity:
                # Decrease the product stock and update ProductSummary
                product.product_stock -= cart_item.quantity
                product.save()
                summary, created = ProductSummary.objects.get_or_create(product_name=product.product_name)
                summary.update_total_stock()
                # Remove the item from the cart
                cart_item.delete()
            else:
                # Handle insufficient stock, you can redirect or show an error message
                return HttpResponseBadRequest("Insufficient stock for some items")

        # # Redirect to a payment success page
        # subject = 'Order Confirmation: Your Reservation Was Successful'
        # message = 'We are delighted to confirm that your reservation has been successfully processed. Your choice in our selection is greatly appreciated! Your selected indoor plants are now reserved for you at our store. To complete your purchase and secure your chosen plants, kindly visit our store location at your earliest convenience.'
        # from_email = settings.EMAIL_HOST_USER  # Your sender email address
        # recipient_list = [order.user.email]
        # send_mail(subject, message, from_email, recipient_list)

        # subject = 'Order Confirmation: Reservation for Indoor Plants'
        # message = f'This is to inform you that the following reservation has been confirmed:\n\n'
        # message += 'Customer Name: [order.user.userprofile.name]\n'  # Replace [Customer Name] with the actual customer's name
        # message += 'Email: [order.user.email]\n'  # Replace [Customer Email] with the actual customer's email
        # message += 'Reserved Indoor Plant:\n'
        # message += '- Plant 1\n'  # Replace with the actual plant names and details
        # message += '- Plant 2\n'
        # # Add more plant details as needed
        # message += '\n'
        # message += 'The customer will be visiting your shop to complete the purchase and pick up the reserved plants.'
        # message += '\n\nThank you for using our reservation service.'
        # from_email = settings.EMAIL_HOST_USER  # Your sender email address
        # recipient_list = [order.seller.email]
        # send_mail(subject, message, from_email, recipient_list)
        return redirect('orders')

    return HttpResponseBadRequest("Invalid request method")

@login_required
def orders(request):
    user_orders = Order.objects.filter(user=request.user)
    order_items = []

    for order in user_orders:
        for item in order.orderitem_set.all():
            review = Review.objects.filter(user=request.user, seller=item.product.seller).first()
            deliveryreview = Deliveryreview.objects.filter(user=request.user, deliveryagent=item.deliveryagent).first()
            if review:
                review_status = review.review_status
                item.review_id = review.pk
                item.review_desc = review.description
            else:
                review_status = 'Pending'
                item.review_id = None
                item.review_desc = None
            
            if deliveryreview:
                agent_review_status = deliveryreview.review_status
                item.delivery_review_id = deliveryreview.pk
                item.delivery_review_desc = deliveryreview.description
            else:
                agent_review_status = 'Pending'
                item.delivery_review_id = None
                item.delivery_review_desc = None
            

            if item.selected_date and item.selected_date < timezone.now().date():
                item.order_not_valid = True
            # Generate QR code for each order
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(f'Order ID: {order.id}\nProduct ID: {item.id}\nProduct: {item.product.product_name}\nUser: {order.user}\n')            
            qr.make(fit=True)
            qr_img = qr.make_image(fill_color="black", back_color="white")

            buffered = BytesIO()
            qr_img.save(buffered, format="PNG")
            item.qr_code_data = base64.b64encode(buffered.getvalue()).decode("utf-8")

            order_items.append((order, item, review_status, agent_review_status))

    context = {
        'order_items': order_items,

    }

    return render(request, 'usertems/orders.html', context)

# ... Your other imports and view functions ...
  
@login_required
def submit_deliveryreview(request):
    if request.method == 'POST':
        agent_id = request.POST.get('agent_id')
        deliveryagent = DeliveryAgent.objects.get(id=agent_id)
        description = request.POST.get('agentdescription')
        review_id = request.POST.get('agentreview_id')  # Get the review_id from the form
        
        # Sentiment Analysis using TextBlob
        sentiment_score = analyze_sentiment(description)

        # Calculate the rating based on sentiment score
        star_rating = map_sentiment_to_rating(sentiment_score)

        if review_id:
            # If review_id is available, it's an edit action
            review = Deliveryreview.objects.get(review_id=review_id)
            review.description = description
            review.rating = star_rating  # Update the rating based on sentiment
            review.save()
        else:
            # It's an add action
            review = Deliveryreview.objects.create(
                user=request.user,
                rating=star_rating,  # Use calculated rating
                description=description,
                deliveryagent=deliveryagent,
                review_status='REVIEWED',
            )
            
        print(review_id)
        userprofile=UserProfile.objects.filter(user=request.user)
        message = "A user has reviewed you"
        Notification.objects.create(
            user=deliveryagent.user, title="Review Added", message=message, is_read=False
        )
        user_subject = 'Review Submitted Successfully'
        user_message = f'Dear {request.user.userprofile.name},\n\n' \
                    'Thank you for submitting your review on our platform. ' \
                    'Your feedback is valuable to us.\n\n' \
                    'Best regards,\n' \
                    'The Budora Team'
        user_from_email = settings.EMAIL_HOST_USER
        user_recipient_list = [request.user.email]

        # Email to the seller
        agent_subject = 'New Review Posted'
        agent_message = f'{deliveryagent.name},\n\n' \
                        f'A new review has been posted by {request.user.userprofile.name}. ' \
                        'You can log in to your account to view the review.\n\n' \
                        'Best regards,\n' \
                        'The Budora Team'
        agent_from_email = settings.EMAIL_HOST_USER
        agent_recipient_list = [deliveryagent.email]

        # Send emails
        send_mail(user_subject, user_message, user_from_email, user_recipient_list, fail_silently=False)
        send_mail(agent_subject, agent_message, agent_from_email, agent_recipient_list, fail_silently=False)
        # Redirect to a success page or the product detail page
        return redirect('orders')

def generate_pdf(request, order_id):
    order = get_object_or_404(Order, id=order_id)

    # Create a Django HTML template for the PDF content
    template = get_template('pdf_order.html')
    context = {'order': order}
    html = template.render(context)

    # Create a PDF file using the HTML content
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="Invoice{order_id}.pdf"'

    # Generate PDF from HTML using xhtml2pdf
    pisa_status = pisa.CreatePDF(html, dest=response)
    if pisa_status.err:
        return HttpResponse('Error generating PDF', status=500)

    return response

def analyze_sentiment(text):
    analysis = TextBlob(text)
    sentiment_score = analysis.sentiment.polarity
    return sentiment_score

def map_sentiment_to_rating(sentiment_score):
    if sentiment_score >= 0.5:
        return 5
    elif sentiment_score >= 0.2:
        return 4
    elif sentiment_score >= -0.2:
        return 3
    elif sentiment_score >= -0.5:
        return 2
    else:
        return 1
   
@login_required
def submit_review(request):
    if request.method == 'POST':
        seller_id = request.POST.get('seller_id')
        seller = Seller.objects.get(id=seller_id)
        description = request.POST.get('description')
        review_id = request.POST.get('review_id')  # Get the review_id from the form

        # Sentiment Analysis using TextBlob
        sentiment_score = analyze_sentiment(description)

        # Calculate the rating based on sentiment score
        star_rating = map_sentiment_to_rating(sentiment_score)

        if review_id:
            # If review_id is available, it's an edit action
            review = Review.objects.get(review_id=review_id)
            review.description = description
            review.rating = star_rating  # Update the rating based on sentiment
            review.save()
        else:
            # It's an add action
            review = Review.objects.create(
                user=request.user,
                rating=star_rating,  # Use calculated rating
                description=description,
                seller=seller,
                review_status='REVIEWED',
            )
        print(review_id)
        userprofile=UserProfile.objects.filter(user=request.user)
        message = "A user has reviewed your store"
        Notification.objects.create(
            user=seller.user, title="Review Added", message=message, is_read=False
        )
        send_review_notification_email(request.user, seller, review)
        # Redirect to a success page or the product detail page
        return redirect('orders')


    
@login_required
def view_orders(request):
    all_orders = Order.objects.all()
    return render(request, 'admin/view_orders.html', {'all_orders': all_orders})



@login_required
def sellerorder(request):
    user = request.user

    # Check if the current user is a seller
    if user.is_staff:
        # If the user is a seller, retrieve the seller profile
        current_seller = user.seller

        # Retrieve the orders for the current seller
        seller_orders = OrderItem.objects.filter(seller=current_seller)

        # Update order_not_valid based on selected_date
     
        for order_item in seller_orders:
            if order_item.selected_date and order_item.selected_date < timezone.now().date():
                order_item.order_not_valid = True
            order_item.save()

        context = {
            'seller': current_seller,
            'seller_orders': seller_orders,
        }

    return render(request, 'seller/sellerorder.html', context)

@login_required
def seller_approve_order(request, order_id):
    order = get_object_or_404(OrderItem, id=order_id)
    if request.method == 'POST':
        order.seller_is_approved = OrderItem.APPROVED  # Set it to 'approved'
        order.save()
        # subject = 'Congratulations! Your License Has Been Approved'
        # message = 'We are delighted to inform you that your license application has been successfully approved. Your dedication and compliance with the necessary requirements have made this approval possible. We appreciate your patience throughout the process. With your approved license, you are now officially recognized and authorized to add your plants. '
        # from_email = settings.EMAIL_HOST_USER  # Your sender email address
        # recipient_list = [order.seller.email]
        # send_mail(subject, message, from_email, recipient_list)
    return redirect('sellerorder')

@login_required
def customer_approve_order(request, order_id):
    order = get_object_or_404(OrderItem, id=order_id)
    if request.method == 'POST':
        order.customer_is_approved = OrderItem.COLLECTED  # Set it to 'approved'
        order.save()
        # subject = 'Congratulations! Your License Has Been Approved'
        # message = 'We are delighted to inform you that your license application has been successfully approved. Your dedication and compliance with the necessary requirements have made this approval possible. We appreciate your patience throughout the process. With your approved license, you are now officially recognized and authorized to add your plants. '
        # from_email = settings.EMAIL_HOST_USER  # Your sender email address
        # recipient_list = [order.seller.email]
        # send_mail(subject, message, from_email, recipient_list)
    return redirect('orders')




from django.shortcuts import render
from django.http import JsonResponse
from .models import ProductSummary,Recommend
from .models import Review  # Import your Review model


def live_search(request):
    if request.method == 'GET':
        search_query = request.GET.get('query', '')
        results = ProductSummary.objects.filter(product_name__icontains=search_query)
        product_data = []

        for product in results:
            # You can add more fields from the ProductSummary model as needed
            product_info = {
                'name': product.product_name,
                'prod_id': product.id,

                 # Include img1 URL
            }
            product_data.append(product_info)

        return JsonResponse({'products': product_data})
    


# myapp/views.py
from django.shortcuts import render
from django.http import JsonResponse
import joblib
import numpy as np
import pandas as pd

def plant_recommendation(request):
    symptoms = ['Light Requirements', 'Watering Frequency', 'Humidity Tolerance', 'Temperature Range','Maintenance Difficulty', 'Toxicity to Pets', 'Aesthetic Appeal', 'Air-Purifying','Indoor Space', 'Price Range', 'Recommended For']
    symptoms = sorted(symptoms)
    context = {'symptoms':symptoms, 'status':'1'}
    return render(request,'recommendation/plantrecommendation.html', context)


nb_model = joblib.load('models/naive_bayes.pkl')

list_a = ['Light Requirements', 'Watering Frequency', 'Humidity Tolerance', 'Temperature Range',
          'Maintenance Difficulty', 'Toxicity to Pets', 'Aesthetic Appeal', 'Air-Purifying',
          'Indoor Space', 'Price Range', 'Recommended For']


@csrf_exempt
def MakePrediction(request):
    s1 = request.POST.get('s1')
    s2 = request.POST.get('s2')
    s3 = request.POST.get('s3')
    s4 = request.POST.get('s4')
    s5 = request.POST.get('s5')
    id = request.POST.get('id')

    list_b = [s1, s2, s3, s4, s5]
    list_c = [0] * len(list_a)
    for symptom in list_b:
        if symptom in list_a:
            list_c[list_a.index(symptom)] = 1
    test = np.array(list_c).reshape(1, -1)
    prediction = nb_model.predict(test)
    result = prediction[0]
    a = Recommend(s1=s1, s2=s2, s3=s3, s4=s4, s5=s5, plant=result, user_id=id)
    a.save()

    return JsonResponse({'status': result})



def predict_result(request):
    userid = request.user.id
    plant = Recommend.objects.all().filter(user_id=userid)
    context = {'plant':plant,'status':'1'}
    return render(request,'recommendation/predict_form.html',context)

    

from django.http import JsonResponse
from django.shortcuts import render
import joblib
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import pandas as pd

def plant_recommendation(request):
    return render(request,'recommendation/plantrecommendation.html')

def recommendation(request):
    model = joblib.load('models/random_forest_model.pkl')
    user = request.user

    if request.method == 'POST':
        # Get the input data from the form
        air_purification = request.POST.get('air_purification_level')
        humidity_increase = request.POST.get('humidity_increase_level')
        stress_reduction = request.POST.get('stress_reduction_level')
        mental_health = request.POST.get('mental_health_level')
        productivity = request.POST.get('productivity_level')
        sleep_improvement = request.POST.get('sleep_improvement_level')
        aesthetic_pleasure = request.POST.get('aesthetic_pleasure_level')
        aromatherapy_level = request.POST.get('aroma_benefit_level')

        input_data = pd.DataFrame({
            'Air Purification': [float(air_purification) if air_purification else 0.0],
            'Humidity Increase': [float(humidity_increase) if humidity_increase else 0.0],
            'Stress Reduction': [float(stress_reduction) if stress_reduction else 0.0],
            'Mental Health': [float(mental_health) if mental_health else 0.0],
            'Productivity': [float(productivity) if productivity else 0.0],
            'Sleep Improvement': [float(sleep_improvement) if sleep_improvement else 0.0],
            'Aromatherapy': [float(aromatherapy_level) if aromatherapy_level else 0.0],
            'Aesthetic Pleasure': [float(aesthetic_pleasure) if aesthetic_pleasure else 0.0],
        })

        

        N = 30
        predicted_probabilities = model.predict_proba(input_data)[0]
        sorted_plants = sorted(zip(model.classes_, predicted_probabilities), key=lambda x: -x[1])
        top_n_recommendations = [plant for plant, _ in sorted_plants[:N]]

        recommended_plants_formatted = [plant.lower().replace(' ', '') for plant in top_n_recommendations]

        recommended_plants = []  # Create an empty list to store matching plants

        for plant_name in recommended_plants_formatted:
            matching_plants = ProductSummary.objects.filter(product_name__icontains=plant_name)
            recommended_plants.extend(matching_plants)

        X_test = pd.read_csv('models/plantsample.csv')  # Load your test data
        y_test = X_test['Plant Name']
        X_test = X_test[['Air Purification', 'Humidity Increase', 'Stress Reduction', 'Mental Health', 'Productivity', 'Sleep Improvement', 'Aromatherapy', 'Aesthetic Pleasure']]
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        print(f"Accuracy of the Random Forest model: {accuracy:.2f}")
        # Now, recommended_plants contains all matching plants
        response_data = {'recommended_plants': top_n_recommendations, 'accuracy': accuracy, 'matching_plants': recommended_plants}
        


    return render(request, 'recommendation/result.html',response_data )



@login_required
def add_recommwishlist(request, product_id):
    product = get_object_or_404(ProductSummary, pk=product_id)
    user = request.user

    # Check if the product is already in the user's cart
    existing_wishlist_item = Wishlist.objects.filter(user=user, product=product).first()
    is_in_wishlist = existing_wishlist_item is not None

    if request.method == 'POST':
        image = product.product_image

        if not is_in_wishlist:
            # If the product is not in the cart, add it to the cart with the specified quantity
            Wishlist.objects.create(user=user, product=product, image=image)
        else:
            print("Already in Cart")

        return redirect('product_single',product_id=product_id)
    return render(request, 'usertems/product.html', {'product': product,'is_in_wishlist': is_in_wishlist})

@login_required
def remove_recommwishlist(request, product_id):
    product = get_object_or_404(ProductSummary, pk=product_id)

    wishlist_item = Wishlist.objects.filter(product=product)
    if request.method == 'POST':
        wishlist_item.delete()
    return redirect('product_single',product_id=product_id) 


@login_required
def qrscan(request, order_id, product_id):
    # Retrieve the parameters from the query string or POST data
    order = get_object_or_404(Order, id=order_id)
    user = request.user

    # Check if the current user is a seller
    if user.is_staff:
        # If the user is a seller, retrieve the seller profile
        current_seller = user.seller

        # Retrieve the orders for the current seller
        seller_orders = OrderItem.objects.filter( seller=current_seller, order=order)


        # Check if there are matching OrderItem objects
        if seller_orders.exists():
            # If there are matching OrderItem objects, update the first one
            seller_orders_item = OrderItem.objects.get(id=product_id, seller=current_seller, order=order)
            seller_orders_item_load = OrderItem.objects.filter(id=product_id, seller=current_seller, order=order, ) 
            if seller_orders_item.delivery_choice == 'reserve':
                if (
                    seller_orders_item.seller_is_approved == 'APPROVED'
                    and seller_orders_item.customer_is_approved == 'COLLECTED'
                ):
                    # If both are approved, show a message and redirect
                    # qr_error_message = "This product has already been approved."
                    context = {
                        # 'qr_error_message': qr_error_message,
                        'seller_orders': seller_orders
                    }
                    
                else:
                    print("01")
                    # Set it to 'approved'
                    seller_orders_item.seller_is_approved = 'APPROVED'
                    seller_orders_item.customer_is_approved = 'COLLECTED'
                    seller_orders_item.save()
                    print("2")
                    qr_error_message = "guyvgyv"

                    context = {
                        'seller_orders': seller_orders_item_load,
                        # 'qr_error_message': qr_error_message,
                    }
                    print("3")
                return render(request, 'seller/sellerorder.html', context)
            else:
                qr_error_message = "This order is to be delivered."
                context = {
                        'qr_error_message': qr_error_message,
                        'seller_orders': seller_orders
                    }
                return render(request, 'seller/sellerorder.html', context)
        else:
            seller_orders_load = OrderItem.objects.filter(seller=current_seller)
            qr_error_message = "This order does not belong to your products."
            context = {
                'qr_error_message': qr_error_message,
                'seller_orders': seller_orders_load
            }
            return render(request, 'seller/sellerorder.html', context)

    # Redirect to the sellerorder page with an error message
    else:
        # Handle the case where the user is not a seller
        return redirect('sellerorder')
 
def nearbystores(request):
    user_profile = UserProfile.objects.get(user=request.user)
    sellers = Seller.objects.all()
    nearby_sellers = []

    if request.method == 'POST':
        latitude = request.POST.get('latitude')
        longitude = request.POST.get('longitude')

        if latitude is not None and longitude is not None:
            user_profile.latitude = latitude
            user_profile.longitude = longitude
            user_profile.save()

    latitude = user_profile.latitude
    longitude = user_profile.longitude
    
    
    for seller in sellers:
        if latitude is not None and longitude is not None:
            # Calculate distance for each seller using haversine
            distance = haversine(seller.latitude, seller.longitude, user_profile.latitude, user_profile.longitude)
            allreviews = Review.objects.filter(seller=seller)
            avg_rating = allreviews.aggregate(Avg('rating'))['rating__avg'] or 0
            print(f"Seller: {seller.name}")
            print(f"Distance: {distance} km\n")
            
            seller.avgrating = avg_rating
            seller.save()
            # Update the seller's distance field in the database
            UserSellerDistance.objects.update_or_create(
                user=request.user,
                seller=seller,
                defaults={'distance': distance}
            )

            
        
    userseller = UserSellerDistance.objects.filter(user=request.user)
    nearby_sellers = userseller.filter(
        distance__isnull=False,
        user=request.user,
    ).order_by('distance')

    context = {
        'nearby_sellers': nearby_sellers,
        
    }

    return render(request, 'usertems/nearbystores.html', context)

def haversine(lat1, lon1, lat2, lon2):
    # Helper function to calculate distance between two points on the Earth's surface
    def convert_coord(coord):
        return float(coord) if coord is not None else 0.0
      
    # Convert latitude and longitude to radians
    lat1, lon1, lat2, lon2 = map(convert_coord, [lat1, lon1, lat2, lon2])
    
    # Haversine formula
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlon / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    distance = 6371.0 * c  # Radius of Earth in kilometers

    return distance

 
@login_required
def store_detail(request, seller_id):
    
    seller = get_object_or_404(Seller, pk=seller_id)
    user_orders = Order.objects.filter(user=request.user)
    userseller = UserSellerDistance.objects.filter(user=request.user,seller=seller)
    if user_orders:
        orders = OrderItem.objects.filter(seller=seller).first()
    else:
        orders = None
    print(orders)
    # user_orders = Order.objects.filter(user=request.user,seller=seller).first()
    review = Review.objects.filter(user=request.user, seller=seller).first()
    allreviews = Review.objects.filter(seller=seller)
    
    if review:
        review_status = review.review_status
        review_id = review.pk  # Add the review_id to the order
        review_desc=review.description
    else:
        review_status = 'Pending'  # Default to "Pending" if no review found
        review_id = None  # Set review_id to None if no review found
        review_desc = None
    user = request.user
   
    avg_rating = allreviews.aggregate(Avg('rating'))['rating__avg'] or 0

    seller_products = seller.products.all()

    context = {
        'seller': seller, 
        'seller_products': seller_products,
        'userseller':userseller,
        'review_status' : review_status,
        'review_id' : review_id,
        'avg_rating': avg_rating,
        'orders': orders,
        'review_desc':review_desc,
    }
    if len(allreviews)>0:
        context['allreviews']=allreviews
        print(len(allreviews))

    return render(request, 'usertems/storedetail.html', context)

@login_required
def submit_review_storeproduct(request):
    if request.method == 'POST':
        seller_id = request.POST.get('seller_id')
        seller = Seller.objects.get(id=seller_id)
        description = request.POST.get('description')
        review_id = request.POST.get('review_id')  # Get the review_id from the form

        # Sentiment Analysis using TextBlob
        sentiment_score = analyze_sentiment(description)

        # Calculate the rating based on sentiment score
        star_rating = map_sentiment_to_rating(sentiment_score)

        if review_id:
            # If review_id is available, it's an edit action
            review = Review.objects.get(review_id=review_id)
            review.description = description
            review.rating = star_rating  # Update the rating based on sentiment
            review.save()
        else:
            # It's an add action
            review = Review.objects.create(
                user=request.user,
                rating=star_rating,  # Use calculated rating
                description=description,
                seller=seller,
                review_status='REVIEWED',
            )
        print(review_id)
        send_review_notification_email(request.user, seller, review)
        # Redirect to a success page or the product detail page
        return redirect('store_detail',seller_id=seller_id)
    
@login_required
def mark_notification_as_read(request):
    if request.method == 'POST':
        notification_id = request.POST.get('notification_id')
        Notification.objects.filter(id=notification_id).update(is_read=True)
    return JsonResponse({'status': 'success'})

@login_required
def notifications(request):
    user = request.user
    notifications = Notification.objects.filter(user=user, is_read=False)

    context = {
        'notifications': [{'id': n.id, 'title': n.title, 'message': n.message} for n in notifications],
        'notification_count': notifications.count()
    }

    return JsonResponse(context)
import string
import random

@login_required
def add_deliveryagent(request):
    sellers = Seller.objects.all()

    
    if request.method == 'POST':
        agent_name = request.POST.get('agent_name')
        address = request.POST.get('place')
        mobile_number = request.POST.get('phone_number')
        email = request.POST.get('email')
        
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        if User.objects.filter(username=email).exists():
            messages.info(request, "Email already registered")
            return redirect('add_deliveryagent')
        
        else:
            user = User.objects.create_user(
                username=email,
                email=email,
                password=password,
            )
            user_profile = UserProfile(user=user, email=email, name=agent_name, address=address, phone_number=mobile_number)
            user_profile.save()
            delivery_agent = DeliveryAgent.objects.create(
                user=user,  # Associate the DeliveryAgent with the user
                name=agent_name,
                email=email,
                contact=mobile_number,
                address=address,     
                # Set the status to 'pending'
            )


            subject = 'Welcome to Budora'
            message = f'Hi {agent_name},\n\nYou have been added as a delivery agent on Budora.\n\nYour login credentials:\nEmail: {email}\nPassword: {password}\n\nThank you for joining our team!'
            from_email = 'mailtoshowvalidationok@gmail.com'  # Replace with your email
            recipient_list = [email]

            send_mail(subject, message, from_email, recipient_list, fail_silently=False)
            messages.success(request, 'Agent Added Successfully')
            return redirect('viewdeliveryagents')

    return render(request, 'admin/add_deliveryagent.html', {'sellers': sellers})



@login_required
def viewsellers(request):
    sellers = Seller.objects.all()
    return render(request, 'admin/viewsellers.html', {'sellers': sellers})

@login_required
def viewdeliveryagents(request):
    deliveryagents = DeliveryAgent.objects.all()
    return render(request, 'admin/viewdeliveryagents.html', {'deliveryagents': deliveryagents})

@login_required   
def agent_index(request):
    deliveryagent = DeliveryAgent.objects.get(user=request.user)
    user_profile = UserProfile.objects.get(user=request.user)
    orderitem_count = OrderItem.objects.filter(deliveryagent=deliveryagent).count()
    orderitem_delivered_count = OrderItem.objects.filter(deliveryagent=deliveryagent,agent_is_approved='DELIVERED').count()
    orderitem_pending_count = OrderItem.objects.filter(deliveryagent=deliveryagent,agent_is_approved='notdelivered').count()

    if request.user.is_authenticated:
        user_profile = UserProfile.objects.get(user=request.user)
        if not user_profile.address and  not user_profile.phone_number and not user_profile.profile_pic:
            message = "Please update your profile with address, phone number, and profile picture."
            Notification.objects.update_or_create(user=request.user, title="Profile Update Required", message=message, defaults={'is_read': False})
        elif not user_profile.address and not user_profile.phone_number:
            message = "Please update your profile with address and phone number"
            Notification.objects.update_or_create(user=request.user, title="Profile Update Required", message=message, defaults={'is_read': False})
        elif not user_profile.profile_pic and not user_profile.phone_number:
            message = "Please update your profile with profile pic and phone number"
            Notification.objects.update_or_create(user=request.user, title="Profile Update Required", message=message, defaults={'is_read': False})
        elif not user_profile.profile_pic and not user_profile.address:
            message = "Please update your profile with address and profile pic"
            Notification.objects.update_or_create(user=request.user, title="Profile Update Required", message=message, defaults={'is_read': False})
        elif not user_profile.address:
            message = "Please update your profile with address."
            Notification.objects.update_or_create(user=request.user, title="Profile Update Required", message=message, defaults={'is_read': False})
        elif not user_profile.phone_number:
            message = "Please update your profile with phone number"
            Notification.objects.update_or_create(user=request.user, title="Profile Update Required", message=message, defaults={'is_read': False})
        elif not user_profile.profile_pic:
            message = "Please update your profile with profile picture."
            Notification.objects.update_or_create(user=request.user, title="Profile Update Required", message=message, defaults={'is_read': False})
        else:
            Notification.objects.filter(
                    user=request.user, title="Profile Update Required"
                ).update(is_read=True)
    
    
    
    allreviews = Deliveryreview.objects.filter(deliveryagent=deliveryagent)
    avg_rating = allreviews.aggregate(Avg('rating'))['rating__avg'] or 0
        

    if request.method == 'POST':
        # Handle form submission
        profile_pic = request.FILES.get('profile_pic')
        owner_name = request.POST.get('owner_name')
        email = request.POST.get('email')
        availability = request.POST.get('availability')
        vehicle_type = request.POST.get('vehicle_type')
        license = request.POST.get('license')
        latitude = request.POST.get('latitude')
        longitude = request.POST.get('longitude')

        # Perform client-side validation here using JavaScript if needed

        # Perform server-side validation if needed
        # if not certification_image or not owner_name or not store_name or not expiry_date_from or not expiry_date_to:
        #     messages.error(request, 'Please fill in all required fields.')
        # else:
            # Create and save the Certification instance
        if 'profile_pic' in request.FILES:
            profile_pic = request.FILES['profile_pic']
            user_profile.profile_pic = profile_pic
            print('got')

        user_profile.latitude = latitude
        user_profile.longitude = longitude
        
        user_profile.save()

        deliveryagent.license_number = license
        deliveryagent.vechicle_type = vehicle_type
        deliveryagent.latitude = latitude
        deliveryagent.longitude = longitude
        deliveryagent.availability = availability
        deliveryagent.is_approved = DeliveryAgent.UPDATED
        
        deliveryagent.save()
    return render(request, 'deliveryagent/agent_index.html', {'deliveryagent': deliveryagent,'orderitem_delivered_count':orderitem_delivered_count,'orderitem_pending_count':orderitem_pending_count,'allreviews':allreviews,'avg_rating':avg_rating,'orderitem_count':orderitem_count})
   


def agent_loggout(request):
    print('Logged Out')
    logout(request)
    if 'username' in request.session:
        del request.session['username']
        request.session.clear()
    return redirect(loginu)

@login_required
def agentorders(request):
    deliveryagent = DeliveryAgent.objects.get(user=request.user)
    return render(request, 'deliveryagent/agentorders.html',{'deliveryagent': deliveryagent})

@login_required
def agentprofile(request):
    user_profile = UserProfile.objects.get(user=request.user)
    deliveryagent = DeliveryAgent.objects.get(user=request.user)
    if request.method == 'POST':
        name = request.POST.get('name')
        
        profile_pic = request.FILES.get('profile_pic')
        phone_number = request.POST.get('phone_number')
        address = request.POST.get('address')
        reset_password = request.POST.get('reset_password')
        old_password = request.POST.get('old_password') 
        

        if 'profile_pic' in request.FILES:
            profile_pic = request.FILES['profile_pic']
            user_profile.profile_pic = profile_pic
            print('got')
        user_profile.name = name
        deliveryagent.name = name
        user_profile.phone_number = phone_number
        deliveryagent.contact = phone_number
        user_profile.address = address
        deliveryagent.address=address
        

        # Check if all three password fields are not empty
        if old_password and reset_password and request.POST.get('cpass') == reset_password:
            if request.user.check_password(old_password):
                # The old password is correct, set the new password
                request.user.set_password(reset_password)
                request.user.save()
                update_session_auth_hash(request, request.user)  # Update the session to prevent logging out
            else:
                messages.error(request, "Incorrect old password. Password not updated.")
        else:
            print("Please fill all three password fields correctly.")
        
        user_profile.reset_password = reset_password
        user_profile.save()
        request.user.save()
        deliveryagent.save()
        return redirect('agentprofile') 

    context = {
        'user_profile': user_profile,
        'deliveryagent': deliveryagent
    }
    return render(request, 'deliveryagent/agent_profile.html', context)

@login_required
def agentorder(request):
    user = request.user

    # If the user is a delivery agent, retrieve the delivery agent profile
    deliveryagent = DeliveryAgent.objects.get(user=user)

    
    # Retrieve the orders for the current delivery agent where payment is not pending
    agent_orders = OrderItem.objects.filter(
        deliveryagent=deliveryagent,
        order__payment_status=Order.PaymentStatusChoices.SUCCESSFUL  # Filter by payment status
    )

    order_items = []
    for order in agent_orders:
        itemorder = order.order
     
        assign = Assigndeliveryagent.objects.get(deliveryagent=deliveryagent,order=order.order)
        billing = assign.billingdetails
        order_items.append((order, itemorder, billing))
    
    context = {
        'deliveryagent': deliveryagent,
        'order_items': order_items,
    }

    return render(request, 'deliveryagent/agentorders.html', context)

def get_billing_details(request, billing_details_id):
    billing_details = BillingDetails.objects.get(pk=billing_details_id)
    data = {
        'first_name': billing_details.first_name,
        'last_name': billing_details.last_name,
        'state': billing_details.state,
        'street_address': billing_details.street_address,
        'apartment_suite_unit': billing_details.apartment_suite_unit,
        'town_city': billing_details.town_city,
        'postcode_zip': billing_details.postcode_zip,
        'phone': billing_details.phone,
        'email': billing_details.email,
    }
    return JsonResponse(data)

def get_seller_details(request, seller_details_id):
    seller = Seller.objects.get(pk=seller_details_id)
    data = {
        'name': seller.name,
        'storename': seller.storename,
        'address': seller.address,
        'landmark': seller.landmark,
        'opening_days': seller.opening_days,
        'opening_time': seller.opening_time,
        'closing_time': seller.closing_time,
        'phone': seller.contact,
        'email': seller.email,
    }
    return JsonResponse(data)

def get_order_product_details(request, order_id):
    try:
        order = Order.objects.get(pk=order_id)
        order_items = OrderItem.objects.filter(order=order)
        
        order_product_details = []
        for order_item in order_items:
            order_product_details.append({
                'product': order_item.product.product_name,  # Assuming 'title' is the attribute representing the name of the product
                'price': order_item.price,
                'quantity': order_item.quantity,
                'total_price': order_item.total_price,
            })
        
        return JsonResponse(order_product_details, safe=False)
    
    except Order.DoesNotExist:
        return JsonResponse({'error': 'Order not found'}, status=404)
    
@login_required
def agent_approve_order(request, order_id):
    order = get_object_or_404(OrderItem, id=order_id)
    if request.method == 'POST':
        order.agent_is_approved = OrderItem.DELIVERED  # Set it to 'approved'
        order.customer_is_approved = OrderItem.COLLECTED 
        order.seller_is_approved = OrderItem.APPROVED 
        order.save()

        # delivery_agent = order.deliveryagent
        # delivery_agent.assigned_timestamp = None
        # delivery_agent.save()
        
    return redirect('agentorder')

@login_required
def deliveryqrscan(request, order_id, product_id):

    order = get_object_or_404(Order, id=order_id)
    user = request.user

    if DeliveryAgent.objects.filter(user=user):
        agent = DeliveryAgent.objects.get(user=user)
        seller_orders = OrderItem.objects.filter(deliveryagent=agent, order=order)
       
        if seller_orders.exists():
            
            seller_orders_item = OrderItem.objects.get(id=product_id, deliveryagent=agent, order=order)
            seller_orders_item_load = OrderItem.objects.filter(id=product_id, deliveryagent=agent, order=order) 
            if seller_orders_item.delivery_choice == 'order':
                if (
                    seller_orders_item.seller_is_approved == 'APPROVED'
                    and seller_orders_item.customer_is_approved == 'collected'
                ):
                    order_items = []
                    for order in seller_orders:
                        itemorder = order.order
                    
                        assign = Assigndeliveryagent.objects.get(deliveryagent=agent,order=order.order)
                        billing = assign.billingdetails
                        order_items.append((order, itemorder, billing))
                    
                    
                    context = {
                            
                        'agent_orders': seller_orders,
                        'deliveryagent':agent,
                        'order_items': order_items,
                    }
                        
                else:
                    print("01")
                    print(agent)
                    seller_orders_item.seller_is_approved = 'APPROVED'
                    seller_orders_item.customer_is_approved = 'collected'
                    seller_orders_item.agent_is_approved = 'DELIVERED' 
                    agent.availability = 'available' 
                    seller_orders_item.save()
                    print("2")
                    qr_error_message = "guyvgyv"
                    order_items = []
                    for order in seller_orders_item_load:
                        itemorder = order.order
                    
                        assign = Assigndeliveryagent.objects.get(deliveryagent=agent,order=order.order)
                        billing = assign.billingdetails
                        order_items.append((order, itemorder, billing))
                    
                    
                    context = {
                    'agent_orders': seller_orders_item_load,
                    'deliveryagent':agent, 
                    'order_items': order_items,
                    }
                    print("3")
                return render(request, 'deliveryagent/agentorders.html', context)
        else:
            seller_orders_load = OrderItem.objects.filter(deliveryagent=agent)
            qr_error_message = "This order does not belong to your products to be delivered."
            order_items = []
            for order in seller_orders_load:
                itemorder = order.order
            
                assign = Assigndeliveryagent.objects.get(deliveryagent=agent,order=order.order)
                billing = assign.billingdetails
                order_items.append((order, itemorder, billing))
    
            context = {
                'qr_error_message': qr_error_message,
                'agent_orders': seller_orders_load,
                'deliveryagent':agent,
                'order_items': order_items,
            }
            return render(request, 'deliveryagent/agentorders.html', context)
    else:
        # Handle the case where the user is not a seller
        return redirect('agentorder')
 
    
@login_required
def status_unavailable(request, deliveryagent_id):
    agent = get_object_or_404(DeliveryAgent, id=deliveryagent_id)
    if request.method == 'POST':
        agent.availability = 'not_available' 
        agent.save()
    return redirect('agent_index')

@login_required
def status_available(request, deliveryagent_id):
    agent = get_object_or_404(DeliveryAgent, id=deliveryagent_id)
    if request.method == 'POST':
        agent.availability = 'available' 
        agent.save()
    return redirect('agent_index')


@login_required
def reserve(request):
    if request.method == 'POST':
        selected_date_str = request.POST.get('selected_date')
        print(selected_date_str)
        selected_date = datetime.strptime(selected_date_str, '%Y-%m-%d').date() if selected_date_str else None

        cart_items = Cart.objects.filter(user=request.user)
        total_price = Decimal(sum(cart_item.product.product_price * cart_item.quantity for cart_item in cart_items))
        currency = 'INR'
        amount = int(total_price * 100)
        
        # Create a Razorpay Order
        razorpay_order = razorpay_client.order.create(dict(
            amount=amount,
            currency=currency,
            payment_capture='0'
        ))

        # Order id of the newly created order
        razorpay_order_id = razorpay_order['id']
        callback_url = '/paymenthandler/'

        # Create an Order outside the loop
        order = Order.objects.create(
            user=request.user,
            total_price=total_price,
            razorpay_order_id=razorpay_order_id,
            payment_status=Order.PaymentStatusChoices.PENDING,
        )

        # Loop through cart items and create OrderItem for each product
        for cart_item in cart_items:
            product = cart_item.product
            price = product.product_price
            quantity = cart_item.quantity
            total_item_price = price * quantity

            order_item = OrderItem.objects.create(
                order=order,
                product=product,
                seller=product.seller,
                quantity=quantity,
                price=price,
                total_price=total_item_price,
                delivery_choice='reserve'
            )

        # Save the selected date in OrderItem
        if selected_date:
            order_item.selected_date = selected_date
            order_item.save()

        # Save the order to generate an order ID
        order.save()
        
        # Create a context dictionary with all the variables you want to pass to the template
        context = {
            'cart_items': cart_items,
            'total_price': total_price,
            'razorpay_order_id': razorpay_order_id,
            'razorpay_merchant_key': settings.RAZOR_KEY_ID,
            'razorpay_amount': amount,
            'currency': currency,
            'callback_url': callback_url,
            'order_item': order_item,
        }
        return render(request, 'usertems/reservepayment.html', context)


def get_item_data(request, item_id):
    try:
        item = OrderItem.objects.get(id=item_id)
        item_data = {
            'order_confirmed': item.order_confirmed,
            'product_dispatched': item.product_dispatched,
            'delivery_order_confirmed': item.delivery_order_confirmed,
            'agent_is_approved': item.agent_is_approved,
        }
        return JsonResponse(item_data)
    except OrderItem.DoesNotExist:
        return JsonResponse({'error': 'Item not found'}, status=404)
    

def get_reserve_item_data(request, item_id):
    try:
        item = OrderItem.objects.get(id=item_id)
        item_data = {
            'order_confirmed': item.order_confirmed,
            'product_dispatched': item.product_dispatched,
            'delivery_order_confirmed': item.waiting_pickup,
            'seller_is_approved': item.seller_is_approved,
        }
        return JsonResponse(item_data)
    except OrderItem.DoesNotExist:
        return JsonResponse({'error': 'Item not found'}, status=404)
    
@login_required
def seller_dispatch_product(request, item_id):
    item = OrderItem.objects.get(id=item_id)
    item.product_dispatched_date = timezone.now()
    item.product_dispatched = True
    item.save()
    return redirect('sellerorder')

@login_required
def seller_quality_check(request, item_id):
    item = OrderItem.objects.get(id=item_id)
    item.order_qualitycheck_date = timezone.now()
    item.order_qualitycheck = True
    item.save()
    return redirect('sellerorder')

@login_required
def seller_process_order(request, item_id):
    item = OrderItem.objects.get(id=item_id)
    item.order_processed_date = timezone.now()
    item.order_processed = True
    item.save()
    return redirect('sellerorder')

@login_required
def seller_confirm_order(request, item_id):
    item = OrderItem.objects.get(id=item_id)
    item.order_confirmed_date = timezone.now()
    item.order_confirmed = True
    item.save()
    return redirect('sellerorder')

@login_required
def seller_waiting_pickup(request, item_id):
    item = OrderItem.objects.get(id=item_id)
    item.waiting_pickup_date = timezone.now()
    item.waiting_pickup = True
    item.save()
    return redirect('sellerorder')

@login_required
def agent_confirm_order(request, item_id):
    item = OrderItem.objects.get(id=item_id)
    item.delivery_order_confirmed_date = timezone.now()
    item.delivery_order_confirmed = True
    item.save()
    return redirect('agentorder')
