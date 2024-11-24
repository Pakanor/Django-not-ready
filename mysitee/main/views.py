from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json
from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import check_password
import jwt
from django.conf import settings
from django.core.mail import send_mail
from datetime import datetime, timedelta
from django.shortcuts import redirect
from django.shortcuts import render
from .forms import registration_form, login_form, add_task, edit_task
from rest_framework.permissions import IsAuthenticated
import requests
from rest_framework.decorators import api_view, permission_classes
from .models import Task


def generate_activation_token(user):
    payload = {
        'user_id': user.id,
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(hours=10)
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    return token


@csrf_exempt
@require_http_methods(["GET"])
def get_Task(request, user_id):
    user = get_object_or_404(User, id=user_id)
    task = Task.objects.filter(user=user)
    task_list = list(task.values('id', 'title', 'description',
                     'completed', 'created_at', 'due_date'))
    return task_list


@csrf_exempt
@require_http_methods(["POST"])
def edit_Task(request, task_id):
    task = get_object_or_404(Task, id=task_id)

    if request.method == 'POST':

        form = edit_task(request.POST, instance=task)

        if form.is_valid():
            form.save()
            return redirect('/home')
        else:
            return render(request, 'templates/home.html', {'edit_form': form, 'error': "Formularz jest nieprawidłowy", 'task': task})
    else:
        form = edit_task(instance=task)

        return render(request, 'templates/home.html', {'edit_form': form, 'task': task})


@csrf_exempt  # Wyłącza ochronę CSRF dla tego widoku (tylko dla API)
def send_email_view(user):

    token = generate_activation_token(user)
    subject = 'Testowy email'
    activation_link = f"http://127.0.0.1:8000/activate/{token}/"

    message = f'Witaj {user.username},\nKliknij w poniższy link, aby aktywować swoje konto:\n{activation_link}'

    from_email = 'parchatkarobert@gmail.com'

    try:
        send_mail(subject, message, from_email, [user.email])
        print("Wysłano e-mail")
    except Exception as e:
        print(f"Wystąpił błąd podczas wysyłania e-maila: {e}")
        return JsonResponse({'error': 'Nie udało się wysłać e-maila'}, status=500)


@csrf_exempt
@require_http_methods(["POST", "GET"])
def create_User(request):

    if request.method == "GET":
        access_token = request.COOKIES.get('access_token')
        if access_token:
            return redirect('/home')
        form = registration_form()

        return render(request, 'templates/page.html', {'form': form})
    if request.method == "POST":
        try:
            try:
                form = registration_form(request.POST)

                if form.is_valid():
                    email = form.cleaned_data.get('email')
                    form.save()
                    send_email_view(User.objects.get(
                        email=email))

                    return redirect('/login')
                else:
                    return JsonResponse({'errors': form.errors}, status=400)

            except ValidationError as e:
                return JsonResponse({'errors': form.errors}, status=400)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON data."}, status=400)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def activate_user(request, token):
    try:

        decode = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        user_id = decode.get('user_id')
        user = User.objects.get(id=user_id)

        if user or not user.is_active:
            user.is_active = True
            user.save()
           # redirect /login
            return JsonResponse({"jest": 'dziala'})
        else:
            return JsonResponse({"e": "cos nie dziala"})
    except jwt.ExpiredSignatureError:
        return JsonResponse({'error': 'Token wygasł'}, status=400)
    except jwt.InvalidTokenError:
        return JsonResponse({'error': 'Nieprawidłowy token'}, status=400)
    except User.DoesNotExist:
        return JsonResponse({'error': 'Użytkownik nie istnieje'}, status=404)


@csrf_exempt
@require_http_methods(["POST", "GET"])
# @login_required(login_url='/home')  # Wymaga zalogowania, przekierowuje na /home
def login_user(request):

    if request.method == 'GET':

        access_token = request.COOKIES.get('access_token')
        if access_token:
            try:
                payload = jwt.decode(
                    access_token, settings.SECRET_KEY, algorithms=['HS256'])
                print("Token jest ważny:", payload)
            except jwt.ExpiredSignatureError:
                print("Token wygasł")
                response = redirect('/login')
                response.delete_cookie('access_token')
                response.delete_cookie('refresh_token')
                return response
            except jwt.InvalidTokenError:
                print("Nieprawidłowy token")
                response = redirect('/login')
                response.delete_cookie('access_token')
                response.delete_cookie('refresh_token')
                return response

        form = login_form()
        print('Token JWT:', request.headers.get('Authorization'))

        return render(request, 'templates/login.html', {'form': form})

    form = login_form(request.POST)
    if request.method == "POST":
        try:

            if form.is_valid():
                password = form.cleaned_data.get("password")
                username = form.cleaned_data.get('username')

                print(username)

                user = User.objects.get(
                    username=username)
                if (check_password(password, user.password)):

                    response = requests.post(
                        'http://localhost:8000/api/token/',
                        data={'username': username, 'password': password}
                    )

                    if response.status_code == 200:
                        tokens = response.json()
                        access_token = tokens.get('access')
                        refresh_token = tokens.get('refresh')

                        response = redirect('/home')
                        response.set_cookie('access_token', access_token)
                        response.set_cookie('refresh_token', refresh_token)

                        return response
                else:
                    return JsonResponse({"nie": "zle haslo "})
            else:
                return JsonResponse({'errors': form.errors}, status=400)

        except User.DoesNotExist as e:
            return JsonResponse({"error": "nie ma"})


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def home(request):
    token = request.headers.get('Authorization')
    t = token.split(' ')[1]  # Wyciągnięcie tokena
    payload = jwt.decode(t, settings.SECRET_KEY, algorithms=['HS256'])
    user_id = payload.get('user_id')  # Pobranie ID użytkownika z payloada
    user = User.objects.get(id=user_id)

    if request.method == 'GET':

        tasks = Task.objects.filter(user=user)

        add_form = add_task()

        return render(request, 'templates/home.html', {'form': add_form,  'tasks': tasks, })
    if request.method == 'POST':
        form = add_task(request.POST)

        if form.is_valid():
            task = form.save(commit=False)  # Nie zapisujemy jeszcze do bazy
            task.user = user  # Przypisujemy użytkownika do zadania
            task.save()  # Zapisujemy zadanie do bazy

            return redirect('/home')

        return render(request, "templates/home.html", {'form': form})


def logout_user(request):
    response = redirect('/login')  # Lub inny widok/strona po wylogowaniu
    print('Token JWT:', request.headers.get('Authorization'))

    response.delete_cookie('access_token')
    response.delete_cookie('refresh_token')
    print('Token JWT:', request.headers.get('Authorization'))

    return response


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def task_delete(request, task_id):
    task = get_object_or_404(Task, id=task_id)
    print("DELETE request received")

    task.delete()

    return redirect('/home')
