from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from rest_framework import status
from rest_framework.test import APIClient
from .models import File, FileAccess , EmailObserver
from unittest.mock import patch

class UserTests(TestCase):

    def setUp(self):
        self.client = Client()
        self.api_client = APIClient()
        self.user = User.objects.create_user(username='testuser', email='testuser@example.com', password='testpassword')
        self.other_user = User.objects.create_user(username='otheruser', email='otheruser@example.com', password='otherpassword')
        self.file = File.objects.create(user=self.user, file_name='testfile.txt', file_url='http://example.com/testfile.txt', file_format='.txt')

    def test_signup(self):
        response = self.api_client.post(reverse('signup'), {'username': 'newuser', 'email': 'newuser@example.com', 'password': 'newpassword'})
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['user'], 'newuser')
        
    def test_login(self):
        response = self.api_client.post(reverse('login'), {'username': 'testuser', 'password': 'testpassword'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_upload_file(self):
        with open('testfile.txt', 'w') as f:
            f.write('test content')

        with open('testfile.txt', 'rb') as f:
            response = self.api_client.post(reverse('upload_file'), {'user_id': self.user.id, 'file': f})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('file_url', response.data)

    def test_download_file(self):
        response = self.api_client.get(reverse('download_file', kwargs={'file_id': self.file.id}))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('file_url', response.data)

    def test_delete_file(self):
        response = self.api_client.delete(reverse('delete_file', kwargs={'file_id': self.file.id}))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'File deleted successfully')

    def test_share_file(self):
        response = self.api_client.post(reverse('share_file'), {'owner_id': self.user.id, 'shared_with_id': self.other_user.id, 'file_id': self.file.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Access granted')

    def test_user_file_access(self):
        response = self.api_client.get(reverse('user_file_access', kwargs={'file_id': self.file.id}))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('data', response.data)

    def test_user_files(self):
        response = self.api_client.post(reverse('user_files'), {'user_id': self.user.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('data', response.data)

    def test_update_file_access(self):
        initial_access_list = [{'user_id': self.other_user.id, 'has_access': True}]
        response = self.api_client.post(reverse('update_file_access'), {'file_id': self.file.id, 'access_list': initial_access_list})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Access updated successfully')

class ObserverTests(TestCase):

    @patch('yourapp.models.send_mail')
    def test_email_observer(self, mock_send_mail):
        user = User.objects.create_user(username='testuser', email='testuser@example.com', password='testpassword')
        owner = User.objects.create_user(username='owner', email='owner@example.com', password='ownerpassword')
        file = File.objects.create(user=owner, file_name='testfile.txt', file_url='http://example.com/testfile.txt', file_format='.txt')

        file_access = FileAccess(file=file, owner=owner, shared_with=user)
        email_observer = EmailObserver()
        file_access.attach(email_observer)
        file_access.save()

        mock_send_mail.assert_called_once_with(
            'Access Granted',
            'You have been granted access to the file "testfile.txt" by owner.',
            'webmaster@example.com',
            [user.email]
        )
