import requests
import json
from django.shortcuts import render, redirect
from django.contrib import messages

API_BASE_URL = 'https://b316a18v1h.execute-api.us-east-1.amazonaws.com/prod/books'

def landing_page(request):
    return render(request, 'landing.html')

def index(request):
    try:
        response = requests.get(API_BASE_URL)
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
            response = requests.post(API_BASE_URL, json=data)
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
            response = requests.put(API_BASE_URL, json=data)
            response.raise_for_status()
            messages.success(request, 'Book updated successfully!')
            return redirect('index')
        except requests.RequestException as e:
            messages.error(request, f"Error updating book: {str(e)}")

    # GET request to fetch book details
    try:
        response = requests.get(f"{API_BASE_URL}?isbn={isbn}")
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


def delete_book(request, isbn):
    try:
        # Send DELETE request with ISBN as a query parameter
        response = requests.delete(f"{API_BASE_URL}?isbn={isbn}")
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
