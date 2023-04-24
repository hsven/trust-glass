from django.urls import path

from . import views

urlpatterns = [
    path("main/", views.homePage, name="Home"),
    path("", views.loginAction, name="Login"),
]