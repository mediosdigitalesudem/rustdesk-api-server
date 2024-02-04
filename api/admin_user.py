# cython:language_level=3
from django.contrib import admin
from api import models
from django import forms
from django.contrib.auth.models import Group
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import ReadOnlyPasswordHashField


class UserCreationForm(forms.ModelForm):
    """A form for creating new users. Includes all the required
    fields, plus a repeated password."""
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Re-enter Password', widget=forms.PasswordInput)

    class Meta:
        model = models.UserProfile
        fields = ('username', 'is_active', 'is_admin')

    def clean_password2(self):
        # Check that the two password entries match
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Password verification failed, the two passwords do not match.")
        return password2

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super(UserCreationForm, self).save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class UserChangeForm(forms.ModelForm):
    """A form for updating users. Includes all the fields on
    the user, but replaces the password field with admin's
    password hash display field."""
    password = ReadOnlyPasswordHashField(label=("Password Hash"), help_text=("<a href=\"../password/\">Click here to change password</a>."))
    
    class Meta:
        model = models.UserProfile
        fields = ('username', 'is_active', 'is_admin')

    def clean_password(self):
        # Regardless of what the user provides, return the initial value.
        # This is done here, rather than on the field, because the
        # field does not have access to the initial value
        return self.initial["password"]

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super(UserChangeForm, self).save(commit=False)
        if commit:
            user.save()
        return user

class UserAdmin(BaseUserAdmin):
    # The forms to add and change user instances
    form = UserChangeForm
    add_form = UserCreationForm
    password = ReadOnlyPasswordHashField(label=("Password Hash"), help_text=("<a href=\"../password/\">Click here to change password</a>."))
    # The fields to be used in displaying the User model.
    # These override the definitions on the base UserAdmin
    # that reference specific fields on auth.User.
    list_display = ('username', 'rid')
    list_filter = ('is_admin', 'is_active')
    fieldsets = (
        ('Basic Information', {'fields': ('username', 'password', 'is_active', 'is_admin', 'rid', 'uuid', 'deviceInfo',)}),
    )
    readonly_fields = ('rid', 'uuid')
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'is_active', 'is_admin', 'password1', 'password2')}
        ),
    )
    
    search_fields = ('username',)
    ordering = ('username',)
    filter_horizontal = ()


admin.site.register(models.UserProfile, UserAdmin)
admin.site.register(models.RustDeskToken, models.RustDeskTokenAdmin)
admin.site.register(models.RustDeskTag, models.RustDeskTagAdmin)
admin.site.register(models.RustDeskPeer, models.RustDeskPeerAdmin)
admin.site.register(models.RustDesDevice, models.RustDesDeviceAdmin)
admin.site.register(models.ShareLink, models.ShareLinkAdmin)
admin.site.unregister(Group)
admin.site.site_header = 'RustDesk Self-Built Web'
admin.site.site_title = 'Undefined'
