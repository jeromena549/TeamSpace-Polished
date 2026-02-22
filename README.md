# Sync - Internal Company Social App

A full-stack internal company social platform for employee connection, directory browsing, and direct messaging.

## Features

### Core Features
- **Authentication**: Secure signup/login with company email restriction (@company.com)
- **User Profiles**: View and edit your profile with avatar, bio, skills, and department
- **Member Directory**: Browse all employees with search by name, department, or skills
- **Direct Messaging**: 1:1 chat between employees with conversation history

### Extra Features
- **Online Status**: Real-time online indicator (active within last 5 minutes)
- **Password Reset**: Token-based password reset (token shown in console for homework version)
- **Profile Privacy**: Option to hide/show email to other members

## Tech Stack

- **Backend**: FastAPI (Python) with MongoDB
- **Frontend**: React with Tailwind CSS and shadcn/ui components
- **Auth**: JWT tokens stored in httpOnly cookies
- **Database**: MongoDB with Motor async driver

## Project Structure

```
/app
├── backend/
│   ├── server.py          # FastAPI application with all routes
│   ├── seed.py            # Database seeding script
│   ├── requirements.txt   # Python dependencies
│   └── .env               # Environment variables
├── frontend/
│   ├── src/
│   │   ├── App.js         # Main React application
│   │   ├── App.css        # Custom styles
│   │   ├── index.css      # Global styles with Tailwind
│   │   └── components/ui/ # shadcn/ui components
│   ├── package.json       # Node dependencies
│   └── .env               # Frontend environment variables
└── README.md
```

## API Routes

### Authentication
- `POST /api/auth/signup` - Register new user
- `POST /api/auth/login` - Login
- `POST /api/auth/logout` - Logout
- `GET /api/auth/me` - Get current user
- `POST /api/auth/forgot-password` - Request password reset
- `POST /api/auth/reset-password` - Reset password with token

### Users
- `GET /api/users` - List members (with search & pagination)
- `GET /api/users/:id` - Get user profile
- `PUT /api/users/me` - Update own profile

### Messages
- `GET /api/messages/conversations` - List conversations
- `GET /api/messages/thread/:userId` - Get chat thread
- `POST /api/messages/thread/:userId` - Send message

## Environment Variables

### Backend (.env)
```
MONGO_URL="mongodb://localhost:27017"
DB_NAME="test_database"
CORS_ORIGINS="*"
COMPANY_EMAIL_DOMAIN="company.com"
INVITE_CODE=""
JWT_SECRET="your-secret-key"
```

### Frontend (.env)
```
REACT_APP_BACKEND_URL=http://localhost:8001
```

## Getting Started

### 1. Install Dependencies

```bash
# Backend
cd backend
pip install -r requirements.txt

# Frontend
cd frontend
yarn install
```

### 2. Seed the Database

```bash
cd backend
python seed.py
```

### 3. Start the Application

The app runs via supervisor (backend on port 8001, frontend on port 3000).

## Demo Accounts

After running the seed script, you can login with:

| Email | Password |
|-------|----------|
| alice@company.com | password123 |
| bob@company.com | password123 |
| carol@company.com | password123 |
| david@company.com | password123 |
| emma@company.com | password123 |

## Security Features

- **Password Hashing**: bcrypt with salt
- **JWT Tokens**: httpOnly cookies, configurable expiry
- **Company Email**: Only @company.com emails allowed
- **XSS Prevention**: HTML escaping in messages
- **Input Validation**: Pydantic models with length limits
- **CORS**: Configurable allowed origins

## Screenshots Description

1. **Login Page**: Clean auth form with company branding, office background image
2. **Members Directory**: Grid of employee cards with avatar, name, title, and skills badges
3. **Profile Page**: Editable profile with avatar, bio, skills, and privacy toggle
4. **Messages List**: Conversation list with online indicators and last message preview
5. **Chat Thread**: Real-time chat interface with sent/received message styling

## How to Demo

1. Login as `alice@company.com` (password: `password123`)
2. Browse the Members Directory - notice online status indicators
3. Click on a member to view their profile
4. Send a message to another member
5. Check Messages to see your conversation history
6. Edit your profile and toggle email visibility
7. Test password reset via Forgot Password (check console for token)
8. Try signing up with a non-company email to see validation

## Author

Built with Emergent AI
