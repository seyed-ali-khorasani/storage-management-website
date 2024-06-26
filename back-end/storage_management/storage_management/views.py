from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status
from django.contrib.auth.hashers import make_password 
from django.contrib.auth.models import User
from datetime import timedelta, datetime, timezone
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth import authenticate


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
    username = request.data.get("username")
    password = request.data.get("password")
    user = authenticate(username=username, password=password)
    if(username or password) is None:
        return Response({'error':'Username and Password are required!'},status=status.HTTP_400_BAD_REQUEST)
    if user is not None:
            refresh = MyTokenObtainPairSerializer.get_token(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'username': refresh['username'],
            },status=status.HTTP_200_OK)
    else:
        return Response({'error': 'Username or Password is incorrect!'}, status=status.HTTP_400_BAD_REQUEST)
    
