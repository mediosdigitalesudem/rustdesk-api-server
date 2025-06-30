# cython:language_level=3
from django.db import models
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser, PermissionsMixin
)
from .models_work import *


class MyUserManager(BaseUserManager):
    def create_user(self, username, password=None):
        if not username:
            raise ValueError('Users must have a username')

        user = self.model(username=username,
        )
 
        user.set_password(password)
        user.save(using=self._db)
        return user
 
    def create_superuser(self, username, password):
        user = self.create_user(username,
            password=password,
            
        )
        user.is_admin = True
        user.save(using=self._db)
        return user


class UserProfile(AbstractBaseUser, PermissionsMixin):
    username = models.CharField('Username', 
                                unique=True,
                                max_length=50)
    
    rid = models.CharField(verbose_name='RustDesk ID', max_length=16)
    uuid = models.CharField(verbose_name='uuid', max_length=60)
    autoLogin = models.BooleanField(verbose_name='Auto Login', default=True)
    rtype = models.CharField(verbose_name='Type', max_length=20)
    deviceInfo = models.TextField(verbose_name='Login Information:', blank=True)
    
    is_active = models.BooleanField(verbose_name='Active', default=True)
    is_admin = models.BooleanField(verbose_name='Admin', default=False)

    # 2FA fields
    otp_secret_key = models.CharField(max_length=255, blank=True, null=True) # Stores the secret key for OTP generation
    is_2fa_enabled = models.BooleanField(default=False) # Flag to check if 2FA is enabled for the user
    otp_recovery_codes = models.TextField(blank=True, null=True) # Stores hashed recovery codes, comma-separated

    objects = MyUserManager()
 
    USERNAME_FIELD = 'username'  # Field used as username
    # REQUIRED_FIELDS should not include 'password' if it's handled by AbstractBaseUser's password management.
    # It's for fields prompted for when creating a user via createsuperuser.
    # Let's assume 'password' is implicitly required by the manager.
    REQUIRED_FIELDS = []  # Fields that must be filled in, password handled by manager
    
    
    def get_full_name(self):
        # The user is identified by their username
        return self.username
 
    def get_short_name(self):
        # The user is identified by their username
        return self.username
 
    def __str__(self):  # __unicode__ on Python 2
        return self.username
 
    def has_perm(self, perm, obj=None):  # Does the user have the specified permission?
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True
 
    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True
        


    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff 
        return self.is_admin

    class Meta:
    
        verbose_name = "User"
        verbose_name_plural = "User List"
        permissions = (
            ("view_task", "Can see available tasks"),
            ("change_task_status", "Can change the status of tasks"),
            ("close_task", "Can remove a task by setting its status as closed"),
        )
