from django.contrib import admin
from django.urls import path , re_path
from . import views
from rest_framework_simplejwt.views import (TokenRefreshView)

urlpatterns = [
    path("admin/", admin.site.urls),
    path('token/', views.MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    re_path('user/signup', views.signup),
    re_path('user/login', views.login),
    path('upload/', views.upload_file, name='upload_file'),
]
