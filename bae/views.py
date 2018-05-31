from django.shortcuts import render
from bae.models import *
from football import UserResponse
from bae.serializer import UsersSerializer
from bae.permissions import IsAuthenticated
from bae.generics import CreateAPIView, UpdateAPIView
from django.contrib.auth.hashers import check_password
from mongoengine.errors import ValidationError as MongoValidationError


class UserAPICreateView(CreateAPIView):
    serializer_class = UsersSerializer
    lookup_url_kwarg = 'id'

    def perform_create(self, serializer):
        response = Users(username=self.request.POST.get('username', None),
                         name=self.request.POST.get('name', None),
                         email=self.request.POST.get('email', None),
                         phone=self.request.POST.get('phone', None),
                         image=self.request.POST.get('image', None),
                         password=self.request.POST.get('password', None))
        response.save()
        return UserResponse.response(self.get_serializer(response).data)


class UserUpdateAPIView(UpdateAPIView):
    permission_classes = [IsAuthenticated]
    lookup_url_kwarg = 'id'
    serializer_class = UsersSerializer
    queryset = Users.objects.all()

    def get_object(self):
        try:
            user_id = self.request.META.get('HTTP_AUTHORIZATION', self.request.query_params.get('key')).split('-')[0]
            user = self.get_queryset().filter(id=user_id).first()
        except MongoValidationError:
            return UserResponse.error_not_found('User does not exist', exception=True)
        if not user:
            return UserResponse.error_not_found('User does not exist', exception=True)
        return user

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        return self.perform_update(serializer)

    def perform_update(self, serializer):
        user = self.get_object()
        user.name = self.request.data.get('name', user.name)
        user.email = self.request.data.get('color', user.email)
        old_password = self.request.data.get('old_password', None)
        new_password = self.request.data.get('new_password', None)
        if old_password and check_password(old_password, user.password):
            user.password = new_password
        else:
            UserResponse.error_bad_request('Invalid old password', exception=True)
        user.save()
        user.reload()
        return UserResponse.response(self.get_serializer(user).data)
