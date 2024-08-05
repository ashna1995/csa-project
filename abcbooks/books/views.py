import requests
import json
import boto3
from botocore.exceptions import ClientError
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.conf import settings

API_BASE_URL = 'https://b316a18v1h.execute-api.us-east-1.amazonaws.com/prod/books'

cognito_client = boto3.client('cognito-idp', region_name=settings.COGNITO_AWS_REGION)


def landing_page(request):
    return render(request, 'landing.html')


cognito_client = boto3.client('cognito-idp', region_name=settings.COGNITO_AWS_REGION)

def signup(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        try:
            response = cognito_client.sign_up(
                ClientId=settings.COGNITO_APP_CLIENT_ID,
                Username=username,
                Password=password,
                UserAttributes=[
                    {'Name': 'email', 'Value': email},
                ]
            )
            print("Sign up successful. Redirecting to confirm_email.")
            messages.success(request, "Sign up successful. Please check your email for the verification code.")
            return redirect('confirm_email')
        except ClientError as e:
            error_message = str(e)
            print(f"Sign up failed: {error_message}")
            return render(request, 'signup.html', {'error': error_message})
    return render(request, 'signup.html')


def confirm_email(request):
    if request.method == 'POST':
        username = request.POST['username']
        confirmation_code = request.POST['confirmation_code']
        try:
            response = cognito_client.confirm_sign_up(
                ClientId=settings.COGNITO_APP_CLIENT_ID,
                Username=username,
                ConfirmationCode=confirmation_code,
            )
            messages.success(request, "Email confirmed successfully. You can now sign in.")
            return redirect('signin')
        except ClientError as e:
            error_message = str(e)
            return render(request, 'confirm_email.html', {'error': error_message})
    return render(request, 'confirm_email.html')


from django.contrib.auth import authenticate, login as auth_login


def signin(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        try:
            print(f"Attempting to sign in user: {username}")  # Debug print
            response = cognito_client.initiate_auth(
                ClientId=settings.COGNITO_APP_CLIENT_ID,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password
                }
            )
            print(f"Cognito response: {response}")  # Debug print
            # Store the tokens in the session
            request.session['id_token'] = response['AuthenticationResult']['IdToken']
            request.session['access_token'] = response['AuthenticationResult']['AccessToken']

            # Authenticate and login the user
            user = authenticate(request, username=username, password=password)
            if user is not None:
                auth_login(request, user)
                messages.success(request, 'Sign in successful.')
                return redirect('index')
            else:
                messages.error(request, 'Authentication failed.')
        except ClientError as e:
            print(f"Cognito error: {str(e)}")  # Debug print
            messages.error(request, str(e))
    return render(request, 'signin.html')


def signout(request):
    logout(request)
    request.session.flush()
    messages.success(request, 'Signed out successfully.')
    return redirect('signin')


def authenticated_request(request, method, url, json=None):
    token = request.session.get('id_token')
    if not token:
        messages.error(request, 'You need to sign in first.')
        return redirect('signin')

    headers = {
        'Authorization': f'Bearer {token}'
    }

    response = requests.request(method, url, headers=headers, json=json)
    return response


from django.contrib.auth.decorators import login_required

@login_required
def index(request):
    try:
        response = authenticated_request(request, 'GET', API_BASE_URL)
        response.raise_for_status()
        data = response.json()

        # Check if the response is a dictionary with 'body' key
        if isinstance(data, dict) and 'body' in data:
            books_str = data['body']
            books = json.loads(books_str)
        else:
            books = data  # Assume it's already a list of books

        if not isinstance(books, list):
            raise ValueError("Expected a list of books")

        for book in books:
            print(f"Book: {book.get('Title', 'No Title')} - ISBN: {book.get('ISBN', 'No ISBN')}")
            if 'ISBN' not in book or not book['ISBN']:
                print(f"Warning: Book '{book.get('Title', 'Unknown')}' has no ISBN")
    except (requests.RequestException, ValueError, json.JSONDecodeError) as e:
        messages.error(request, f"Error fetching books: {str(e)}")
        books = []

    return render(request, 'index.html', {'books': books})

@login_required
def add_book(request):
    if request.method == 'POST':
        isbn = request.POST['isbn']
        title = request.POST['title']
        author = request.POST['author']
        publisher = request.POST['publisher']
        year = request.POST['year']
        data = {
            'ISBN': isbn,
            'Title': title,
            'Authors': author,
            'Publisher': publisher,
            'Year': year,
        }
        try:
            response = authenticated_request(request, 'POST', API_BASE_URL, json=data)
            response.raise_for_status()
            response_data = response.json()
            print(f"API Response: {response_data}")  # Add this line for debugging
            if response_data.get('statusCode') == 200:
                messages.success(request, 'Book added successfully!')
            else:
                messages.error(request, f"Error adding book: {response_data.get('body', 'Unknown error')}")
            return redirect('index')
        except requests.RequestException as e:
            messages.error(request, f"Error adding book: {str(e)}")
            print(f"Request Exception: {str(e)}")  # Add this line for debugging
    return render(request, 'add_book.html')


@login_required
def edit_book(request, isbn):
    if request.method == 'POST':
        title = request.POST['title']
        author = request.POST['author']
        publisher = request.POST['publisher']
        year = request.POST['year']
        data = {
            'ISBN': isbn,
            'Title': title,
            'Authors': author,
            'Publisher': publisher,
            'Year': year,
        }
        try:
            response = authenticated_request(request, 'PUT', API_BASE_URL, json=data)
            response.raise_for_status()
            messages.success(request, 'Book updated successfully!')
            return redirect('index')
        except requests.RequestException as e:
            messages.error(request, f"Error updating book: {str(e)}")

    # GET request to fetch book details
    try:
        response = authenticated_request(request, 'GET', f"{API_BASE_URL}?isbn={isbn}")
        response.raise_for_status()
        data = response.json()

        # Check if the response is a dictionary with 'body' key
        if isinstance(data, dict) and 'body' in data:
            book_str = data['body']
            book = json.loads(book_str)
        else:
            book = data  # Assume it's already the book data

        # Ensure book is a dictionary and has an ISBN
        if not isinstance(book, dict) or 'ISBN' not in book:
            raise ValueError("Invalid book data received from API")

        print(f"Fetched book data: {book}")  # Add this line for debugging

    except (requests.RequestException, ValueError, json.JSONDecodeError) as e:
        messages.error(request, f"Error fetching book details: {str(e)}")
        return redirect('index')

    return render(request, 'edit_book.html', {'book': book})


@login_required
def delete_book(request, isbn):
    try:
        # Send DELETE request with ISBN as a query parameter
        response = authenticated_request(request, 'DELETE', f"{API_BASE_URL}?isbn={isbn}")
        response.raise_for_status()

        # Parse the response
        result = response.json()
        if isinstance(result, dict) and 'body' in result:
            message = json.loads(result['body'])
        else:
            message = result

        if response.status_code == 200:
            messages.success(request, message)
        else:
            messages.error(request, f"Error deleting book: {message}")
    except requests.RequestException as e:
        messages.error(request, f"Error deleting book: {str(e)}")
    return redirect('index')
