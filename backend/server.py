"""
Internal Company Social App - Backend Server
Features: Auth, User Profiles, Directory, Direct Messaging, Online Status, Password Reset
"""
from fastapi import FastAPI, APIRouter, HTTPException, Depends, Response, Request, Query
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import secrets
import hashlib
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr, ConfigDict, field_validator
from typing import List, Optional
import uuid
import bcrypt
import jwt
from datetime import datetime, timezone, timedelta

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Configuration from environment
COMPANY_EMAIL_DOMAIN = os.environ.get('COMPANY_EMAIL_DOMAIN', 'company.com')
INVITE_CODE = os.environ.get('INVITE_CODE', '')
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRY_HOURS = 24

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app
app = FastAPI(title="Sync - Internal Company Social App")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ===================== MODELS =====================

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=100)
    name: str = Field(min_length=2, max_length=100)
    inviteCode: Optional[str] = None
    
    @field_validator('email')
    @classmethod
    def validate_company_email(cls, v):
        if not v.endswith(f'@{COMPANY_EMAIL_DOMAIN}'):
            raise ValueError(f'Email must end with @{COMPANY_EMAIL_DOMAIN}')
        return v

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    department: Optional[str] = Field(None, max_length=100)
    title: Optional[str] = Field(None, max_length=100)
    skills: Optional[List[str]] = None
    avatarUrl: Optional[str] = None
    bio: Optional[str] = Field(None, max_length=500)
    showEmail: Optional[bool] = None

class UserResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    email: Optional[str] = None
    name: str
    department: Optional[str] = None
    title: Optional[str] = None
    skills: List[str] = []
    avatarUrl: Optional[str] = None
    bio: Optional[str] = None
    showEmail: bool = True
    lastSeenAt: Optional[str] = None
    isOnline: bool = False
    createdAt: str

class MessageCreate(BaseModel):
    body: str = Field(min_length=1, max_length=5000)

class MessageResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    senderId: str
    receiverId: str
    body: str
    createdAt: str

class ConversationResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    userId: str
    userName: str
    userAvatar: Optional[str] = None
    lastMessage: str
    lastMessageAt: str
    isOnline: bool = False

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    newPassword: str = Field(min_length=8, max_length=100)

class AuthResponse(BaseModel):
    message: str
    user: Optional[UserResponse] = None

# ===================== HELPERS =====================

def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode(), hashed.encode())

def create_jwt_token(user_id: str) -> str:
    """Create JWT token for user session"""
    payload = {
        'user_id': user_id,
        'exp': datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS),
        'iat': datetime.now(timezone.utc)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_jwt_token(token: str) -> Optional[dict]:
    """Decode and validate JWT token"""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def is_user_online(last_seen: Optional[str]) -> bool:
    """Check if user was active in the last 5 minutes"""
    if not last_seen:
        return False
    try:
        last_seen_dt = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
        return (datetime.now(timezone.utc) - last_seen_dt).total_seconds() < 300
    except:
        return False

def escape_html(text: str) -> str:
    """Escape HTML to prevent XSS attacks"""
    return (text
        .replace('&', '&amp;')
        .replace('<', '&lt;')
        .replace('>', '&gt;')
        .replace('"', '&quot;')
        .replace("'", '&#x27;'))

async def get_current_user(request: Request) -> dict:
    """Auth middleware - Get current user from JWT cookie or Authorization header"""
    token = request.cookies.get('auth_token')
    
    # Also check Authorization header for API testing
    if not token:
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
    
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    payload = decode_jwt_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    user = await db.users.find_one({'id': payload['user_id']}, {'_id': 0, 'passwordHash': 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    # Update lastSeenAt for online status tracking
    await db.users.update_one(
        {'id': payload['user_id']},
        {'$set': {'lastSeenAt': datetime.now(timezone.utc).isoformat()}}
    )
    
    return user

def user_to_response(user: dict, include_email: bool = False) -> dict:
    """Convert user document to response format"""
    show_email = user.get('showEmail', True)
    return {
        'id': user['id'],
        'email': user.get('email') if (include_email or show_email) else None,
        'name': user.get('name', ''),
        'department': user.get('department'),
        'title': user.get('title'),
        'skills': user.get('skills', []),
        'avatarUrl': user.get('avatarUrl'),
        'bio': user.get('bio'),
        'showEmail': show_email,
        'lastSeenAt': user.get('lastSeenAt'),
        'isOnline': is_user_online(user.get('lastSeenAt')),
        'createdAt': user.get('createdAt', '')
    }

# ===================== AUTH ROUTES =====================

@api_router.post("/auth/signup", response_model=AuthResponse)
async def signup(user_data: UserCreate, response: Response):
    """Register a new user with company email validation"""
    # Validate invite code if configured
    if INVITE_CODE and user_data.inviteCode != INVITE_CODE:
        raise HTTPException(status_code=400, detail="Invalid invite code")
    
    # Check if email already exists
    existing = await db.users.find_one({'email': user_data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user document
    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    
    user_doc = {
        'id': user_id,
        'email': user_data.email,
        'passwordHash': hash_password(user_data.password),
        'name': user_data.name,
        'department': None,
        'title': None,
        'skills': [],
        'avatarUrl': None,
        'bio': None,
        'showEmail': True,
        'lastSeenAt': now,
        'createdAt': now,
        'updatedAt': now
    }
    
    await db.users.insert_one(user_doc)
    
    # Create JWT token and set cookie
    token = create_jwt_token(user_id)
    response.set_cookie(
        key='auth_token',
        value=token,
        httponly=True,
        samesite='none',
        secure=True,
        max_age=JWT_EXPIRY_HOURS * 3600
    )
    
    return {
        'message': 'Account created successfully',
        'user': user_to_response(user_doc, include_email=True)
    }

@api_router.post("/auth/login", response_model=AuthResponse)
async def login(credentials: UserLogin, response: Response):
    """Login with email and password"""
    user = await db.users.find_one({'email': credentials.email}, {'_id': 0})
    
    if not user or not verify_password(credentials.password, user['passwordHash']):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Update lastSeenAt
    await db.users.update_one(
        {'id': user['id']},
        {'$set': {'lastSeenAt': datetime.now(timezone.utc).isoformat()}}
    )
    
    # Create JWT token and set cookie
    token = create_jwt_token(user['id'])
    response.set_cookie(
        key='auth_token',
        value=token,
        httponly=True,
        samesite='none',
        secure=True,
        max_age=JWT_EXPIRY_HOURS * 3600
    )
    
    return {
        'message': 'Login successful',
        'user': user_to_response(user, include_email=True)
    }

@api_router.post("/auth/logout")
async def logout(response: Response):
    """Logout by clearing the auth cookie"""
    response.delete_cookie('auth_token')
    return {'message': 'Logged out successfully'}

@api_router.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    """Get current authenticated user"""
    return user_to_response(current_user, include_email=True)

@api_router.post("/auth/forgot-password")
async def forgot_password(request: ForgotPasswordRequest):
    """Request password reset - token is printed to console (homework version)"""
    user = await db.users.find_one({'email': request.email}, {'_id': 0})
    
    # Always return success to prevent email enumeration
    if not user:
        return {'message': 'If the email exists, a reset link has been sent'}
    
    # Generate reset token
    reset_token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    
    reset_doc = {
        'id': str(uuid.uuid4()),
        'userId': user['id'],
        'token': reset_token,
        'expiresAt': expires_at.isoformat(),
        'used': False
    }
    
    await db.password_resets.insert_one(reset_doc)
    
    # Print token to console (homework version - in production would send email)
    logger.info("=" * 60)
    logger.info(f"PASSWORD RESET TOKEN for {request.email}")
    logger.info(f"Token: {reset_token}")
    logger.info(f"Use this token to reset your password")
    logger.info("=" * 60)
    
    return {'message': 'If the email exists, a reset link has been sent', 'token': reset_token}

@api_router.post("/auth/reset-password")
async def reset_password(request: ResetPasswordRequest, response: Response):
    """Reset password using token"""
    reset_doc = await db.password_resets.find_one({
        'token': request.token,
        'used': False
    }, {'_id': 0})
    
    if not reset_doc:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    
    # Check if token expired
    expires_at = datetime.fromisoformat(reset_doc['expiresAt'].replace('Z', '+00:00'))
    if datetime.now(timezone.utc) > expires_at:
        raise HTTPException(status_code=400, detail="Reset token has expired")
    
    # Update password
    new_hash = hash_password(request.newPassword)
    await db.users.update_one(
        {'id': reset_doc['userId']},
        {'$set': {'passwordHash': new_hash, 'updatedAt': datetime.now(timezone.utc).isoformat()}}
    )
    
    # Mark token as used
    await db.password_resets.update_one(
        {'id': reset_doc['id']},
        {'$set': {'used': True}}
    )
    
    # Clear auth cookie
    response.delete_cookie('auth_token')
    
    return {'message': 'Password reset successful. Please login with your new password.'}

# ===================== USER ROUTES =====================

@api_router.get("/users", response_model=List[UserResponse])
async def list_users(
    search: Optional[str] = Query(None, description="Search by name, department, or skills"),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    current_user: dict = Depends(get_current_user)
):
    """List all users with optional search and pagination"""
    query = {}
    
    if search:
        # Search across name, department, and skills (case-insensitive)
        search_regex = {'$regex': search, '$options': 'i'}
        query = {
            '$or': [
                {'name': search_regex},
                {'department': search_regex},
                {'skills': search_regex}
            ]
        }
    
    skip = (page - 1) * limit
    users = await db.users.find(query, {'_id': 0, 'passwordHash': 0}).skip(skip).limit(limit).to_list(limit)
    
    return [user_to_response(u) for u in users]

@api_router.get("/users/{user_id}", response_model=UserResponse)
async def get_user(user_id: str, current_user: dict = Depends(get_current_user)):
    """Get a specific user's public profile"""
    user = await db.users.find_one({'id': user_id}, {'_id': 0, 'passwordHash': 0})
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return user_to_response(user)

@api_router.put("/users/me", response_model=UserResponse)
async def update_me(update_data: UserUpdate, current_user: dict = Depends(get_current_user)):
    """Update current user's profile"""
    update_dict = {k: v for k, v in update_data.model_dump().items() if v is not None}
    
    if not update_dict:
        return user_to_response(current_user, include_email=True)
    
    update_dict['updatedAt'] = datetime.now(timezone.utc).isoformat()
    
    await db.users.update_one(
        {'id': current_user['id']},
        {'$set': update_dict}
    )
    
    updated_user = await db.users.find_one({'id': current_user['id']}, {'_id': 0, 'passwordHash': 0})
    return user_to_response(updated_user, include_email=True)

# ===================== MESSAGING ROUTES =====================

@api_router.get("/messages/conversations", response_model=List[ConversationResponse])
async def list_conversations(current_user: dict = Depends(get_current_user)):
    """List all conversations for current user with last message"""
    user_id = current_user['id']
    
    # Get all messages involving current user
    messages = await db.messages.find({
        '$or': [
            {'senderId': user_id},
            {'receiverId': user_id}
        ]
    }, {'_id': 0}).sort('createdAt', -1).to_list(1000)
    
    # Group by conversation partner
    conversations = {}
    for msg in messages:
        partner_id = msg['receiverId'] if msg['senderId'] == user_id else msg['senderId']
        if partner_id not in conversations:
            conversations[partner_id] = msg
    
    # Get partner user details
    result = []
    for partner_id, last_msg in conversations.items():
        partner = await db.users.find_one({'id': partner_id}, {'_id': 0, 'passwordHash': 0})
        if partner:
            result.append({
                'userId': partner_id,
                'userName': partner.get('name', 'Unknown'),
                'userAvatar': partner.get('avatarUrl'),
                'lastMessage': last_msg['body'][:100],  # Truncate for preview
                'lastMessageAt': last_msg['createdAt'],
                'isOnline': is_user_online(partner.get('lastSeenAt'))
            })
    
    # Sort by last message time
    result.sort(key=lambda x: x['lastMessageAt'], reverse=True)
    return result

@api_router.get("/messages/thread/{user_id}", response_model=List[MessageResponse])
async def get_thread(user_id: str, current_user: dict = Depends(get_current_user)):
    """Get message thread with another user"""
    current_id = current_user['id']
    
    # Verify target user exists
    target_user = await db.users.find_one({'id': user_id}, {'_id': 0})
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get messages between the two users
    messages = await db.messages.find({
        '$or': [
            {'senderId': current_id, 'receiverId': user_id},
            {'senderId': user_id, 'receiverId': current_id}
        ]
    }, {'_id': 0}).sort('createdAt', 1).to_list(1000)
    
    return messages

@api_router.post("/messages/thread/{user_id}", response_model=MessageResponse)
async def send_message(user_id: str, message: MessageCreate, current_user: dict = Depends(get_current_user)):
    """Send a message to another user"""
    current_id = current_user['id']
    
    # Verify target user exists
    target_user = await db.users.find_one({'id': user_id}, {'_id': 0})
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Cannot message yourself
    if user_id == current_id:
        raise HTTPException(status_code=400, detail="Cannot send message to yourself")
    
    # Create message document (escape HTML to prevent XSS)
    message_doc = {
        'id': str(uuid.uuid4()),
        'senderId': current_id,
        'receiverId': user_id,
        'body': escape_html(message.body),
        'createdAt': datetime.now(timezone.utc).isoformat()
    }
    
    await db.messages.insert_one(message_doc)
    
    return message_doc

# ===================== HEALTH CHECK =====================

@api_router.get("/")
async def root():
    return {"message": "Sync API - Internal Company Social App"}

@api_router.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
