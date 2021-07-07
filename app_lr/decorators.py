from django.contrib import messages
from django.shortcuts import redirect

def login_required(function):

    def wrapper(request, *args):
        if 'usuario' not in request.session:
            return redirect('/')
        resp=function(request, *args)
        return resp
    
    return wrapper


def val_admin(function):

    def wrapper(request, *args):
        if request.session['usuario']['rol'] != "ADMINISTRADOR":
            messages.error(request, "El usuario no es administrador por lo tanto no tiene acceso , usuario corresponde a " + request.session['usuario']['rol'])
            
            return redirect("/panel")
        resp=function(request, *args)
        return resp
    
    return wrapper