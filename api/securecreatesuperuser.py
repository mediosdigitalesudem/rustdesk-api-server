import getpass
from django.core.management.commands.createsuperuser import Command as BaseCommand

class Command(BaseCommand):
    help = 'Create a superuser with a securely entered password'

    def handle(self, *args, **options):
        password = getpass.getpass(prompt='Password: ')
        password2 = getpass.getpass(prompt='Password (again): ')
        if password != password2:
            self.stderr.write("Error: Passwords don't match")
            return
        options['password'] = password
        super().handle(*args, **options)
