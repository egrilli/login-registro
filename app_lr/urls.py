from django.urls import path
from . import views
urlpatterns = [
    path('', views.index),
    path('registro', views.registro),
    path('logearse',views.logearse),
    path('panel',views.panel),
    path('logout',views.logout),
    path('colaborador',views.colaborador),
    path('administrador',views.administrador)

]
