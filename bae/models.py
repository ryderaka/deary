# from django.db import models
from __future__ import unicode_literals
import datetime
from django.utils.crypto import get_random_string, random
from mongoengine import *


class Pages(Document):
    title = StringField(max_length=64, required=True)
    description = StringField(max_length=500, required=True)
    images = StringField(max_length=50, default=None)
    language = StringField(max_length=50, default=None)
    privacy = StringField(max_length=50, default=None)
    font = StringField(max_length=50, default=None)
    comments = DictField(default=None)
    tags = ListField()
    star = IntField()
    editors = ListField()
    is_archived = BooleanField(default=None)
    is_deleted = BooleanField(default=None)
    timestamp = StringField(max_length=50, default=None)
    created_at = DateTimeField(default=datetime.datetime.now, required=True)
    updated_at = DateTimeField(blank=True, null=True)

    def save(self, *args, **kwargs):
        self.updated_at = datetime.datetime.utcnow()
        return super(Pages, self).save(*args, **kwargs)


class Users(Document):
    username = StringField(max_length=50, required=True)
    name = StringField(max_length=50, required=False)
    email = EmailField(unique=True, max_length=120, required=True)
    phone = IntField()
    user_type = StringField(max_length=50, default=None)
    image = StringField(max_length=50, default=None)
    password = StringField(max_length=120, required=True)
    api_key = StringField(max_length=120, required=False)
    following = ListField()
    followers = ListField()
    timezone = StringField(max_length=50, default=None)
    theme = StringField(max_length=50, default=None)
    is_verified = BooleanField(default=None)
    is_archived = BooleanField(default=None)
    is_deleted = BooleanField(default=None)
    created_at = DateTimeField(default=datetime.datetime.now, required=True)
    updated_at = DateTimeField(blank=True, null=True)

    meta = {
        'collection': 'users',
        'indexes': [
            {'fields': ['email'], 'unique': True}
        ]
    }

    def save(self, *args, **kwargs):
        self.last_updated = datetime.datetime.now()
        from django.contrib.auth.hashers import make_password
        self.password = make_password(self.password)
        return super(Users, self).save(*args, **kwargs)

    @classmethod
    def pre_save(cls, sender, document, **kwargs):
        # from django.contrib.auth.hashers import make_password
        # document.password = make_password(document.password)
        if not document.api_key:
            document.api_key = get_random_string(random.randint(50, 60))

signals.post_init.connect(Users.pre_save, sender=Users)

