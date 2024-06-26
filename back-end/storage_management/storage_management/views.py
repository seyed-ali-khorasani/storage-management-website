from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status
from django.contrib.auth.hashers import make_password 
from django.contrib.auth.models import User
from datetime import timedelta, datetime, timezone
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth import authenticate ,get_user_model
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib import messages
from django.core.mail import EmailMessage
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from .models import File
from django.conf import settings
import boto3
from botocore.exceptions import NoCredentialsError
import os

from .tokens import account_activation_token



# views.py or a separate settings file
FILE_TYPE_ICONS = {
    'mp3': '/static/icons/mp3_icon.png',
    'mp4': '/static/icons/mp4_icon.png',
    'pdf': '/static/icons/pdf_icon.png',
    'word': '/static/icons/word_icon.png',
    # Add other file types and their corresponding icons
}






class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims
        token['username'] = user.username
        # ...

        return token
class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer



@api_view(['GET'])
def activate(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except:
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()

        messages.success(request, "Thank you for your email confirmation. Now you can login your account.")
        return Response({'M': 'Done'}, status=status.HTTP_404_NOT_FOUND)
    else:
        messages.error(request, "Activation link is invalid!")

    return Response({'Error': 'Error'}, status=status.HTTP_404_NOT_FOUND)




def activateEmail(request,user,to_email):
    mail_subject = "Activate Your User Account."
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = account_activation_token.make_token(user)
    domain = get_current_site(request).domain
    protocol = 'https' if request.is_secure() else 'http'

    print(f"Token :{token}")
    
    message = render_to_string("template_activate_account.html",{
        'user':user.username,
        'domain':domain,
        'uid':uid,
        'token':token,
        'protocol':protocol
    })

    email = EmailMessage(mail_subject,message,to={to_email})
    if email.send():
        messages.success(request, f'Dear <b>{user.username}</b>, please go to your email <b>{to_email}</b> inbox and click on \
            received activation link to confirm and complete the registration. <b>Note:</b> Check your spam folder.')
    else :
        messages.error(request, f'Problem sending email to {to_email}, check if you typed it correctly.')



# USER SIGN UP
@api_view(['POST'])
def signup(request):

    username = request.data.get("username")
    email = request.data.get("email")
    password = request.data.get("password")

    if (username or password) is None:
        return Response({'error': 'Username and password are required'}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(username=username).exists():
        return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)
    

    User.objects.create(username = username , email = email)

    user = User.objects.get(username = username)
    user.set_password(password)
    user.save()
    
    return Response({"user":user.username},status=status.HTTP_201_CREATED)

    

# USER LOGIN
@api_view(['POST'])
def login(request):
    username_or_email = request.data.get("username")
    password = request.data.get("password")
    
    if(username_or_email or password) is None:
        return Response({'error':'Email or Username and Password are required!'},status=status.HTTP_400_BAD_REQUEST)

    if "@" in username_or_email:
        user = authenticate(email=username_or_email, password=password)
    else:
        user = authenticate(username=username_or_email, password=password)

    if user is not None:
            refresh = MyTokenObtainPairSerializer.get_token(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'username': refresh['username'],
            },status=status.HTTP_200_OK)
    else:
        return Response({'error': 'Username or Password is incorrect!'}, status=status.HTTP_400_BAD_REQUEST)
    



@api_view(['POST'])
def upload_file(request):

    user_id = request.POST['user_id']
    file = request.FILES['file']
    
    # گرفتن اطلاعات کاربر
    user = User.objects.get(id=user_id)


    file_format = os.path.splitext(file.name)[1].lower()  # فرمت فایل را دریافت می‌کند

    # آپلود فایل به ابر آرمان
    s3 = boto3.client('s3',
                        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                        region_name=settings.AWS_S3_REGION_NAME,
                        endpoint_url=settings.AWS_S3_ENDPOINT_URL)

    try:
        s3.upload_fileobj(file, settings.AWS_STORAGE_BUCKET_NAME, file.name)
        file_url = f"{settings.AWS_S3_CUSTOM_DOMAIN}/{file.name}"
        
        # ذخیره‌سازی اطلاعات فایل در دیتابیس
        file_record = File(user=user, file_name=file.name, file_format=file_format, file_url=file_url)
        file_record.save()
        
        return JsonResponse({'status': 'success', 'file_url': file_url})
    except NoCredentialsError:
        return JsonResponse({'status': 'error', 'message': 'Credentials not available'})

