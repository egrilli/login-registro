from django.db import models
import re

# Create your models here.
class UserManager(models.Manager):
    def validador_basico(self, postData):
        EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
        SOLO_LETRAS = re.compile(r'^[a-zA-Z. ]+$')

        errors = {}

        if len(postData['firstname']) < 3:
            errors['firstname_len'] = "nombre debe tener al menos 3 caracteres de largo";

        if len(postData['lastname']) < 2:
            errors['lastname_len'] = "apellido debe tener al menos 2 caracteres de largo";

        if not EMAIL_REGEX.match(postData['email']):
            errors['email'] = "correo invalido"


        if not SOLO_LETRAS.match(postData['firstname']) or not SOLO_LETRAS.match(postData['lastname']):
            errors['solo_letras'] = "solo letras en nombre y apellido porfavor"

        if len(postData['password']) < 8:
            errors['password'] = "contraseña debe tener al menos 8 caracteres";

        if postData['password'] != postData['password_confirm'] :
            errors['password_confirm'] = "contraseña y confirmar contraseña no son iguales. "

        return errors

class User(models.Model):
    firstname = models.CharField(max_length=100)
    lastname = models.CharField(max_length=100)
    email = models.CharField(max_length=200, unique=True)
    password = models.CharField(max_length=70)
    rol = models.CharField(max_length=30, default='COLABORADOR')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = UserManager()
    def __str__(self):
        return f"{self.firstname} {self.lastname}"
    def __repr__(self):
        return f"{self.firstname} {self.lastname}"