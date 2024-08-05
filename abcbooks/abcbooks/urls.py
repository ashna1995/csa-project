from django.contrib import admin
from django.urls import path
from books import (views)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.landing_page, name='landing_page'),
    path('books/', views.index, name='index'),
    path('add/', views.add_book, name='add_book'),
    path('edit/<str:isbn>/', views.edit_book, name='edit_book'),
    path('delete/<str:isbn>/', views.delete_book, name='delete_book'),
]

