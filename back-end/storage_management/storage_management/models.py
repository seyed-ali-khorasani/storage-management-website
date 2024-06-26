from django.db import models
from datetime import timezone
from django.contrib.auth.models import User

class UserImage(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    image = models.ImageField(upload_to='profile_images/')

class File(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file_name = models.CharField(max_length=255)
    upload_time = models.DateTimeField(auto_now_add=True)
    file_url = models.URLField()
    file_format = models.CharField(max_length=50,default=None)  # فیلد جدید برای ذخیره فرمت فایل