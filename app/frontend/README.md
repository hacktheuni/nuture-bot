# Frontend - Chatbot UI

A simple single-page chatbot UI for the Nuture Bot FastAPI backend.

## Features

- ✅ User Registration
- ✅ User Login
- ✅ Chat Interface with AI responses
- ✅ Clean, modern UI with animations
- ✅ Responsive design

## Running the Frontend

### Option 1: Using Python HTTP Server (Recommended)

```bash
# From the project root
cd app/frontend
python3 server.py
```

The frontend will be available at: **http://localhost:8080**

### Option 2: Using Python's built-in HTTP server

```bash
# From app/frontend directory
python3 -m http.server 8080
```

Then open: **http://localhost:8080/index.html**

## Running Both Backend and Frontend

### Terminal 1 - Backend (FastAPI)
```bash
# From project root
uvicorn app.main:app --reload --port 8000
```

### Terminal 2 - Frontend
```bash
# From project root
cd app/frontend
python3 server.py
```

## API Configuration

The frontend is configured to connect to the backend at `http://localhost:8000`.

If your backend runs on a different port, update the `API_BASE_URL` constant in `index.html`:

```javascript
const API_BASE_URL = 'http://localhost:YOUR_PORT';
```

## API Endpoints Used

### Authentication
- `POST /auth/register` - User registration
- `POST /auth/login/email` - User login

### Chat
- `POST /chat/query` - Send chat message and get AI response

## Usage

1. Start your FastAPI backend on port 8000
2. Start the frontend server on port 8080
3. Open http://localhost:8080 in your browser
4. Register a new account or login with existing credentials
5. Start chatting with the AI!

## Notes

- The frontend uses localStorage to store the access token
- Token is automatically included in API requests
- Session expires when token is invalid (401 response)

