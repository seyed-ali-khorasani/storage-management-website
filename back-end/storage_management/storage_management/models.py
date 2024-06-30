from django.db import models
from datetime import timezone
from django.contrib.auth.models import User
from abc import ABC, abstractmethod
from django.core.mail import send_mail
from django.conf import settings
from django.core.paginator import Paginator
from rest_framework.pagination import PageNumberPagination



class UserImage(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    image = models.ImageField(upload_to='profile_images/')

class File(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file_name = models.CharField(max_length=255)
    upload_time = models.DateTimeField(auto_now_add=True)
    file_url = models.URLField()
    file_format = models.CharField(max_length=50,default=None)  
    file_size = models.FloatField(default=0)





class Subject:
    def __init__(self):
        self._observers = []

    def attach(self, observer):
        if observer not in self._observers:
            self._observers.append(observer)

    def detach(self, observer):
        try:
            self._observers.remove(observer)
        except ValueError:
            pass

    def notify(self):
        for observer in self._observers:
            observer.update(self)


class FileAccess(models.Model, Subject):
    file = models.ForeignKey(File, on_delete=models.CASCADE)
    owner = models.ForeignKey(User, related_name='owned_files', on_delete=models.CASCADE)
    shared_with = models.ForeignKey(User, related_name='shared_files', on_delete=models.CASCADE)

    def __init__(self, *args, **kwargs):
        models.Model.__init__(self, *args, **kwargs)  # Initialize the Django model
        Subject.__init__(self)  # Initialize the Subject

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        self.notify()

class Observer(ABC):
    @abstractmethod
    def update(self, subject):
        pass

class EmailObserver(Observer):
    def update(self, subject):
        user = subject.shared_with
        owner = subject.file.user
        file_name = subject.file.file_name
        send_mail(
            'Access Granted',
            f'You have been granted access to the file "{file_name}" by {owner.username}.',
            settings.DEFAULT_FROM_EMAIL,
            [user.email]
        )



class CustomPagination(PageNumberPagination):
    page_size = 24
    page_size_query_param = 'page_size'
    max_page_size = 100

