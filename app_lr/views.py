from django.contrib import messages
from django.shortcuts import redirect, render
from app_lr.models import User
import bcrypt

def index(request):

    return render(request, 'index.html')


def registro(request):
    if request.method == "POST":
        errors = User.objects.validador_basico(request.POST)
        if len(errors) > 0:
            for key, value in errors.items():
                messages.error(request, value)

            request.session['registro_nombre'] =  request.POST['firstname']
            request.session['registro_apellido'] =  request.POST['lastname']
            request.session['registro_email'] =  request.POST['email']

        else:
            request.session['registro_nombre'] = ""
            request.session['registro_apellido'] = ""
            request.session['registro_email'] = ""

            password_encryp = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt()).decode() 

            usuario_nuevo = User.objects.create(
                firstname = request.POST['firstname'],
                lastname=request.POST['lastname'],
                email=request.POST['email'],
                password=password_encryp
            )

            messages.success(request, "El usuario fue agregado con exito.")
            
        return redirect("/registro")
    else:
        return render(request, 'registro.html')


def logearse(request):
    if request.method == "POST":
        print(request.POST)
        user = User.objects.filter(email=request.POST['email'])
        if user:
            log_user = user[0]

            if bcrypt.checkpw(request.POST['password'].encode(), log_user.password.encode()):

                usuario = {
                    "id" : log_user.id,
                    "name": f"{log_user}",
                    "email": log_user.email,
                    "rol":log_user.rol
                }

                request.session['usuario'] = usuario
                messages.success(request, "Logeado correctamente.")
                return redirect("/panel")
            else:
                messages.error(request, "Password o Email  malas.")
        else:
            messages.error(request, "Email o password malas.")

        return redirect("/logearse")
    else:
        return render(request, 'logearse.html')

    return render(request, 'logearse.html')

def panel(request):
    if 'usuario' not in request.session:
        return redirect("/")

    return render(request, 'panel.html')


def logout(request):
    if 'usuario' in request.session:
        del request.session['usuario']
        messages.error(request, "Sesion Cerrada")
    return redirect("/")


def colaborador(request):
    if 'usuario' not in request.session:
        return redirect("/")

    return render(request, 'colaborador.html')

def administrador(request):
    if 'usuario' not in request.session:
        return redirect("/")

    if request.session['usuario']['rol'] != "ADMINISTRADOR":
        messages.error(request, "El usuario no es administrador por lo tanto no tiene acceso , usuario corresponde a " + request.session['usuario']['rol'])
    

    return render(request, 'administrador.html')

