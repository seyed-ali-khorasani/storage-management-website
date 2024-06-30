from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status
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
from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User
from .models import File , FileAccess , EmailObserver
from django.conf import settings
import boto3
from botocore.exceptions import NoCredentialsError
import os
from django.core.paginator import Paginator
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import Q
from django.utils.html import strip_tags
from django.core.mail import EmailMultiAlternatives
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken
import math
import logging 




from .tokens import account_activation_token




FILE_ICONS = {
    'image': 'icons/Image.png',
    'pdf': 'icons/pdf.png',
    'video': 'icons/Audio.png',
    'music': 'icons/Music.png',
    'unknown': 'icons/others.png',
    'profile' : 'icons/profile.png'
}

def get_icon_for_file(file_format):
    if file_format == ".png" or file_format == ".jpeg" or file_format == ".jpg":
        return FILE_ICONS['image']
    elif file_format == '.pdf':
        return FILE_ICONS['pdf']
    elif file_format == '.mp4':
        return FILE_ICONS['video']
    elif file_format == '.mp3':
        return FILE_ICONS['music']
    else:
        return FILE_ICONS['unknown']






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
    print("mjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj")

    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()

        messages.success(request, "Thank you for your email confirmation. Now you can login your account.")
        return Response({'M': 'Done'}, status=status.HTTP_200_OK)
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
    print("mjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj")
    html_code = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Document</title></head><body><a href="http://localhost:3000/user/activate/'+ str(uid)+'/' + str(token)+'">active your email</a></body></html>'
    text_content = strip_tags(html_code)
    email = EmailMultiAlternatives(
        subject='Thanks for you registeration',
        body=text_content,
        from_email="ehsan.akbajj@gmail.com",
        to=[to_email]
    )
    email.attach_alternative(html_code,"text/html")
    email.send()
    return Response({"m":"email send"})
    #email = EmailMessage(mail_subject,message,to={to_email})
    # if email.send():
    #     messages.success(request, f'Dear <b>{user.username}</b>, please go to your email <b>{to_email}</b> inbox and click on \
    #         received activation link to confirm and complete the registration. <b>Note:</b> Check your spam folder.')
    # else :
    #     messages.error(request, f'Problem sending email to {to_email}, check if you typed it correctly.')



# USER SIGN UP
@api_view(['POST'])
def signup(request):

    username = request.data.get("username")
    email = request.data.get("email")
    password = request.data.get("password")

    print(username)
    print(password)

    if (username or password) is None:
        return Response({'error': 'Username and password are required'}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(username=username).exists():
        return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)
    

    User.objects.create(username = username , email = email)

    user = User.objects.get(username = username)
    user.set_password(password)
    user.is_active=False
    user.save()

    activateEmail(request, user, email)
    
    return Response({"user":user.username},status=status.HTTP_201_CREATED)

    

# USER LOGIN
@api_view(['POST'])
def login(request):
    username_or_email = request.data.get("username")
    password = request.data.get("password")
    
    if not username_or_email or not password:
        return Response({'error':'Email or Username and Password are required!'}, status=status.HTTP_400_BAD_REQUEST)

    if "@" in username_or_email:
        user_query = User.objects.filter(email=username_or_email)
    else:
        user_query = User.objects.filter(username=username_or_email)

    if not user_query.exists():
        return Response({'error': 'Username or Password is incorrect!'}, status=status.HTTP_400_BAD_REQUEST)

    user = user_query.first()

    if not user.is_active:
        return Response({'error': 'Not Active Account'}, status=status.HTTP_401_UNAUTHORIZED)

    # Authenticate user
    user = authenticate(username=user.username, password=password)

    if user is not None:
        refresh = MyTokenObtainPairSerializer.get_token(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'username': refresh['username'],
        }, status=status.HTTP_200_OK)
    else:
        return Response({'error': 'Username or Password is incorrect!'}, status=status.HTTP_400_BAD_REQUEST)



@api_view(['POST'])
def upload_file(request):

    print(request.headers.get('Authorization'))
    authentication_classes = [JWTAuthentication]

    # Validate the token and get the user
    token = request.headers.get('Authorization').split()[1]
    jwt_auth = JWTAuthentication()
    try:
        validated_token = jwt_auth.get_validated_token(token)
        user = jwt_auth.get_user(validated_token)
    except InvalidToken:
        return Response({'error': 'Invalid token!'}, status=status.HTTP_401_UNAUTHORIZED)


    file = request.FILES['file']
    
    
    file_size = file.size  # Get the file size

    file_format = os.path.splitext(file.name)[1].lower()  

    
    s3 = boto3.client('s3',
                        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                        region_name=settings.AWS_S3_REGION_NAME,
                        endpoint_url=settings.AWS_S3_ENDPOINT_URL)

    try:
        s3.upload_fileobj(file, settings.AWS_STORAGE_BUCKET_NAME, file.name)
        file_url = f"{settings.AWS_S3_CUSTOM_DOMAIN}/{file.name}"
        
       
        file_record = File(user=user, file_name=file.name, file_format=file_format, file_url=file_url, file_size=file_size)
        file_record.save()
        
        return JsonResponse({'M': 'Your file uploaded succesfully', 'file_url': file_url})
    except NoCredentialsError:
        return JsonResponse({'status': 'error', 'message': 'Credentials not available'})

@api_view(['GET'])
def download_file(request, file_id):

    file_record = get_object_or_404(File, id=file_id)
    
    
    s3 = boto3.client('s3',
                      aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                      aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                      region_name=settings.AWS_S3_REGION_NAME,
                      endpoint_url=settings.AWS_S3_ENDPOINT_URL)
    
    
    try:
        file_url = s3.generate_presigned_url('get_object',
                                             Params={'Bucket': settings.AWS_STORAGE_BUCKET_NAME,
                                                     'Key': file_record.file_name},
                                             ExpiresIn=3600)  # لینک با اعتبار یک ساعت
        return JsonResponse({'status': 'success', 'file_url': file_url})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})


@api_view(['GET'])
def delete_file(request, file_id):
    
    file_record = get_object_or_404(File, id=file_id)
    
   
    s3 = boto3.client('s3',
                        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                        region_name=settings.AWS_S3_REGION_NAME,
                        endpoint_url=settings.AWS_S3_ENDPOINT_URL)
    
    
    try:
        s3.delete_object(Bucket=settings.AWS_STORAGE_BUCKET_NAME, Key=file_record.file_name)
        
        
        file_record.delete()
        
        return JsonResponse({'status': 'success', 'message': 'File deleted successfully'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})
    
    
@api_view(['POST'])
def share_file(request):
    owner_id = request.data.get('owner_id')
    shared_with_id = request.data.get('shared_with_id')
    file_id = request.data.get('file_id')
    
    owner = get_object_or_404(User, id=owner_id)
    shared_with = get_object_or_404(User, id=shared_with_id)
    file = get_object_or_404(File, id=file_id, user=owner)
    
   
    access_record, created = FileAccess.objects.update_or_create(
        file=file,
        owner=owner,
        shared_with=shared_with,
    )
    
    return JsonResponse({'status': 'success', 'message': 'Access granted'})

    
@api_view(['GET'])
def user_file_access(request, file_id):
    file_record = get_object_or_404(File, id=file_id)
    
    
    owner = file_record.user
    
    
    access_records = FileAccess.objects.filter(file=file_record)
    users_with_access = User.objects.filter(id__in=access_records.values('shared_with')).exclude(id=owner.id).order_by('username')
    
    
    users_without_access = User.objects.exclude(id__in=[user.id for user in users_with_access]).exclude(id=owner.id).order_by('username')
    
    access_list = [{'id': user.id, 'username': user.username,'email':user.email,'profile_image': request.build_absolute_uri(settings.STATIC_URL + FILE_ICONS['profile']), 'have_access': True} for user in users_with_access]
    no_access_list = [{'id': user.id, 'username': user.username, 'email':user.email,'profile_image': request.build_absolute_uri(settings.STATIC_URL + FILE_ICONS['profile']),'have_access': False} for user in users_without_access]
    
    combined_list = access_list + no_access_list
    
    return JsonResponse({'status': 'success', 'data': combined_list})



@api_view(['GET'])
def search_user(request):

    username = request.query_params.get('username', '').strip()
    file_id = request.query_params.get('id', '').strip()
   
    file_record = get_object_or_404(File, id=file_id)
   


   
    users_data = User.objects.filter(Q(username__icontains=username)).exclude(id=file_record.user.id)

    if users_data.exists():
        user_list = []
        for user in users_data:
            
            have_access = FileAccess.objects.filter(file=file_record, shared_with=user).exists()

            user_data = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'profile_image': request.build_absolute_uri(settings.STATIC_URL + FILE_ICONS['profile']),
                'have_access': have_access  # True if user has access, False otherwise
            }
            user_list.append(user_data)

        return Response({"data": user_list}, status=status.HTTP_200_OK)
    else:
        return Response({'error': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)



class CustomPagination(PageNumberPagination):
    page_size = 24
    page_size_query_param = 'page_size'
    max_page_size = 100

def format_upload_time(upload_time):
    # Example format: "day time: pm or am, month: jun, oct, or others, date: day of generated"
    return {
        'time': upload_time.strftime("%I:%M"),
        'typeee':upload_time.strftime("%p"),
        'month': upload_time.strftime("%b"),
        'date': upload_time.strftime("%d")
    }

def convert_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"


@api_view(['GET'])
def user_files(request):
    authentication_classes = [JWTAuthentication]

    # Validate the token and get the user
    token = request.headers.get('Authorization').split()[1]
    jwt_auth = JWTAuthentication()
    try:
        validated_token = jwt_auth.get_validated_token(token)
        user = jwt_auth.get_user(validated_token)
    except InvalidToken:
        return Response({'error': 'Invalid token!'}, status=status.HTTP_401_UNAUTHORIZED)

    user_id = user.id
    page_number = request.query_params.get('page', 1)

    if not user_id:
        return Response({'status': 'error', 'message': 'User ID is required'}, status=400)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'status': 'error', 'message': 'User not found'}, status=404)

    owned_files = File.objects.filter(user=user).order_by('-upload_time')
    owned_files_list = []
    total_size = 0
    for file in owned_files:
        formatted_time = format_upload_time(file.upload_time)
        owned_files_list.append({
            'id': file.id,
            'name': file.file_name,
            'space': convert_size(file.file_size),
            'file_format': file.file_format,
            'image': request.build_absolute_uri(settings.STATIC_URL + get_icon_for_file(file.file_format)),
            'owner_access': True,
            'time': formatted_time['time'],
            'day_time': formatted_time['typeee'],
            'month': formatted_time['month'],
            'date': formatted_time['date']
        })
        total_size += file.file_size

    accessed_files_records = FileAccess.objects.filter(shared_with=user).select_related('file').order_by('-file__upload_time')
    accessed_files_list = []
    for record in accessed_files_records:
        formatted_time = format_upload_time(record.file.upload_time)
        accessed_files_list.append({
            'id': record.file.id,
            'name': record.file.file_name,
            'space': convert_size(record.file.file_size),
            'file_format': record.file.file_format,
            'image': request.build_absolute_uri(settings.STATIC_URL + get_icon_for_file(record.file.file_format)),
            'owner_access': False,
            'time': formatted_time['time'],
            'day_time': formatted_time['typeee'],
            'month': formatted_time['month'],
            'date': formatted_time['date']
        })
        total_size += record.file.file_size

    combined_list = owned_files_list + accessed_files_list

    #combined_list = sorted(combined_list, key=lambda x: x.get('upload_time', 0), reverse=True)

    combined_list = sorted(combined_list, key=lambda x: x['id'], reverse=True)

    paginator = Paginator(combined_list, 24)  

    try:
        page_obj = paginator.page(page_number)
    except EmptyPage:
        return Response({'status': 'error', 'message': 'Page not found'}, status=404)

    data = {
        'status': 'success',
        'total_pages': paginator.num_pages,
        'current_page': page_obj.number,
        'total_items': paginator.count,
        'data': list(page_obj),
        'total': convert_size(total_size)
    }

    return JsonResponse(data)


@api_view(['POST'])
def update_file_access(request):
    file_id = request.data.get('file_id')
    file_record = get_object_or_404(File, id=file_id)
    
    
    new_access_list = request.data.get('access_list', [])
    
    
    current_access_records = FileAccess.objects.filter(file=file_record)
    current_access_users = set(current_access_records.values_list('shared_with', flat=True))
    
   
    new_access_users = set([user['id'] for user in new_access_list if user['have_access']])
    
    
    users_to_remove_access = current_access_users - new_access_users
    
    
    users_to_add_access = new_access_users - current_access_users
    
    
    FileAccess.objects.filter(file=file_record, shared_with_id__in=users_to_remove_access).delete()
    
   
    for user_id in users_to_add_access:
        user = get_object_or_404(User, id=user_id)
        file_access = FileAccess(file=file_record, shared_with=user, owner=file_record.user)
        email_observer = EmailObserver()
        file_access.attach(email_observer)
        file_access.save()
    
    return JsonResponse({'status': 'success', 'message': 'Access updated successfully'})




@api_view(['GET'])
def test(request):
    authentication_classes = [JWTAuthentication]

    # Validate the token and get the user
    token = request.headers.get('Authorization').split()[1]
    jwt_auth = JWTAuthentication()
    try:
        validated_token = jwt_auth.get_validated_token(token)
        user = jwt_auth.get_user(validated_token)
    except InvalidToken:
        return Response({'error': 'Invalid token!'}, status=status.HTTP_401_UNAUTHORIZED)

    user_id = user.id
    page_number = request.query_params.get('page', 1)
    search_term = request.query_params.get('search', '').strip()

    print("Debug message: Search term =", search_term)

    if not user_id:
        return Response({'status': 'error', 'message': 'User ID is required'}, status=400)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'status': 'error', 'message': 'User not found'}, status=404)


    # Search in owned files
    owned_files = File.objects.filter(user=user, file_name__icontains=search_term).order_by('file_name')
    # Log owned files
   
    owned_files_list = []
    total_size = 0
    for file in owned_files:
        formatted_time = format_upload_time(file.upload_time)
        owned_files_list.append({
            'id': file.id,
            'name': file.file_name,
            'space': convert_size(file.file_size),
            'file_format': file.file_format,
            'image': request.build_absolute_uri(settings.STATIC_URL + get_icon_for_file(file.file_format)),
            'owner_access': True,
            'time': formatted_time['time'],
            'day_time': formatted_time['typeee'],
            'month': formatted_time['month'],
            'date': formatted_time['date']
        })
        total_size += file.file_size

    # Search in accessed files
    accessed_files_records = FileAccess.objects.filter(shared_with=user, file__file_name__icontains=search_term).select_related('file')
    # Log accessed files
   
    accessed_files_list = []
    for record in accessed_files_records:
        formatted_time = format_upload_time(record.file.upload_time)
        accessed_files_list.append({
            'id': record.file.id,
            'name': record.file.file_name,
            'space': convert_size(record.file.file_size),
            'file_format': record.file.file_format,
            'image': request.build_absolute_uri(settings.STATIC_URL + get_icon_for_file(record.file.file_format)),
            'owner_access': False,
            'time': formatted_time['time'],
            'day_time': formatted_time['typeee'],
            'month': formatted_time['month'],
            'date': formatted_time['date']
        })
        total_size += record.file.file_size

    combined_list = owned_files_list + accessed_files_list

    #combined_list = sorted(combined_list, key=lambda x: x['upload_time'], reverse=True)

    paginator = Paginator(combined_list, 24)  # Show 24 items per page

    try:
        page_obj = paginator.page(page_number)
    except EmptyPage:
        return Response({'status': 'error', 'message': 'Page not found'}, status=404)

    data = {
        'status': 'success',
        'total_pages': paginator.num_pages,
        'current_page': page_obj.number,
        'total_items': paginator.count,
        'data': list(page_obj),
        'total': convert_size(total_size)
    }

    return JsonResponse(data)