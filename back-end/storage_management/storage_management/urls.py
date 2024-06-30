from django.contrib import admin
from django.urls import path , re_path
from . import views
from rest_framework_simplejwt.views import (TokenRefreshView)
from django.conf.urls.static import static
from django.conf import settings

urlpatterns = [
    path("admin/", admin.site.urls),
    path('token/', views.MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    re_path('user/signup', views.signup),
    re_path('user/login', views.login),
    path('upload/', views.upload_file, name='upload_file'),
    path('download/<int:file_id>/', views.download_file, name='download_file'),
    path('share/', views.share_file, name='share_file'),
    path('user_file_access/<int:file_id>/', views.user_file_access, name='file_access_user_list'),
    re_path('user_files', views.user_files),
    path('remove/<int:file_id>/', views.delete_file, name='delete_file'),
    path('update_access/', views.update_file_access, name='update_file_access'),
    re_path('search', views.search_user, name='search'),
    path('activate/<uidb64>/<token>',views.activate,name="activate"),
    path('test/', views.test, name='search_user_files'),
]
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATICFILES_DIRS[0])
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
