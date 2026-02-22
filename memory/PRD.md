# Sync - Internal Company Social App PRD

## Original Problem Statement
Build an internal company social app for a single organization where only employees can join. Features include:
- Sign up and login with secure authentication
- Company email restriction (@company.com)
- User profile (view + edit)
- Employee directory with search (name, department, skills)
- Direct messaging between employees (1:1)
- Online status tracking (lastSeenAt)
- Password reset flow

## User Choices
- Frontend: React with Tailwind CSS + shadcn/ui
- Authentication: Server-side sessions (JWT in httpOnly cookies)
- Messaging: HTTP-only (no Socket.io)
- Extra features: Online Status (B) + Password Reset (D)

## Architecture
- **Backend**: FastAPI (Python) on port 8001
- **Frontend**: React on port 3000
- **Database**: MongoDB
- **Auth**: JWT tokens in httpOnly cookies

## User Personas
1. **Employee**: Needs to find colleagues, view profiles, send messages
2. **New Hire**: Needs to sign up with company email, set up profile
3. **Team Lead**: Needs to search employees by department/skills

## Core Requirements (Static)
- [x] Company email validation (@company.com)
- [x] Secure password hashing (bcrypt)
- [x] Session-based authentication
- [x] User profile CRUD
- [x] Employee directory with search
- [x] 1:1 direct messaging
- [x] Online status indicator
- [x] Password reset flow
- [x] Profile privacy setting (show/hide email)

## What's Been Implemented (Jan 22, 2026)
- Full authentication flow (signup, login, logout)
- Password reset with token (printed to console)
- User profile page with edit functionality
- Members directory with search by name/department/skills
- Member profile view with online status
- Messaging: conversations list and chat threads
- Privacy toggle for email visibility
- XSS prevention in messages
- Demo data seeding with 5 users and sample messages

## API Routes Implemented
### Auth
- POST /api/auth/signup
- POST /api/auth/login
- POST /api/auth/logout
- GET /api/auth/me
- POST /api/auth/forgot-password
- POST /api/auth/reset-password

### Users
- GET /api/users (with search & pagination)
- GET /api/users/:id
- PUT /api/users/me

### Messages
- GET /api/messages/conversations
- GET /api/messages/thread/:userId
- POST /api/messages/thread/:userId

## Demo Accounts
| Email | Password |
|-------|----------|
| alice@company.com | password123 |
| bob@company.com | password123 |
| carol@company.com | password123 |
| david@company.com | password123 |
| emma@company.com | password123 |

## Prioritized Backlog
### P0 (Done)
- All core requirements implemented

### P1 (Nice to have)
- Real-time messaging with Socket.io
- Email notifications
- File attachments in messages
- User profile pictures upload

### P2 (Future)
- Group messaging/channels
- @mentions
- Message reactions
- User blocking
- Activity feed

## Next Tasks
1. Add Socket.io for real-time messaging (optional)
2. Add file attachments to messages
3. Add invite code requirement configuration
4. Add rate limiting on auth endpoints
5. Add user avatars upload functionality
