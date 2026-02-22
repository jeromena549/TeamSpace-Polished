"""
Seed script for Sync - Internal Company Social App
Creates demo users and messages for testing
"""
import asyncio
import uuid
import bcrypt
from datetime import datetime, timezone, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
import os
from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

# Demo users
DEMO_USERS = [
    {
        "email": "alice@company.com",
        "password": "password123",
        "name": "Alice Johnson",
        "department": "Engineering",
        "title": "Senior Software Engineer",
        "skills": ["Python", "React", "MongoDB", "AWS"],
        "bio": "Full-stack developer with 5 years of experience. Love building scalable applications.",
        "avatarUrl": "https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=200",
        "showEmail": True
    },
    {
        "email": "bob@company.com",
        "password": "password123",
        "name": "Bob Smith",
        "department": "Engineering",
        "title": "DevOps Engineer",
        "skills": ["Docker", "Kubernetes", "CI/CD", "Linux"],
        "bio": "Infrastructure enthusiast. Making deployments smooth since 2018.",
        "avatarUrl": "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=200",
        "showEmail": True
    },
    {
        "email": "carol@company.com",
        "password": "password123",
        "name": "Carol Williams",
        "department": "Design",
        "title": "UX Designer",
        "skills": ["Figma", "User Research", "Prototyping", "Design Systems"],
        "bio": "Passionate about creating intuitive user experiences.",
        "avatarUrl": "https://images.unsplash.com/photo-1438761681033-6461ffad8d80?w=200",
        "showEmail": False
    },
    {
        "email": "david@company.com",
        "password": "password123",
        "name": "David Chen",
        "department": "Product",
        "title": "Product Manager",
        "skills": ["Agile", "Product Strategy", "Analytics", "Roadmapping"],
        "bio": "Building products that users love. Data-driven decision maker.",
        "avatarUrl": "https://images.unsplash.com/photo-1500648767791-00dcc994a43e?w=200",
        "showEmail": True
    },
    {
        "email": "emma@company.com",
        "password": "password123",
        "name": "Emma Davis",
        "department": "Marketing",
        "title": "Marketing Lead",
        "skills": ["Content Strategy", "SEO", "Social Media", "Analytics"],
        "bio": "Telling our company story, one campaign at a time.",
        "avatarUrl": "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=200",
        "showEmail": True
    }
]

async def seed_database():
    print("=" * 60)
    print("SEEDING DATABASE")
    print("=" * 60)
    
    # Clear existing data
    await db.users.delete_many({})
    await db.messages.delete_many({})
    await db.password_resets.delete_many({})
    print("Cleared existing data")
    
    # Create users
    user_ids = {}
    now = datetime.now(timezone.utc)
    
    for i, user_data in enumerate(DEMO_USERS):
        user_id = str(uuid.uuid4())
        user_ids[user_data["email"]] = user_id
        
        # Vary lastSeenAt for demo purposes
        last_seen = now - timedelta(minutes=i * 30)  # First user is online, others progressively older
        
        user_doc = {
            "id": user_id,
            "email": user_data["email"],
            "passwordHash": hash_password(user_data["password"]),
            "name": user_data["name"],
            "department": user_data["department"],
            "title": user_data["title"],
            "skills": user_data["skills"],
            "avatarUrl": user_data["avatarUrl"],
            "bio": user_data["bio"],
            "showEmail": user_data["showEmail"],
            "lastSeenAt": last_seen.isoformat(),
            "createdAt": (now - timedelta(days=30)).isoformat(),
            "updatedAt": now.isoformat()
        }
        
        await db.users.insert_one(user_doc)
        print(f"Created user: {user_data['name']} ({user_data['email']})")
    
    # Create some demo messages
    messages = [
        ("alice@company.com", "bob@company.com", "Hey Bob! Can you help me with the Docker setup?", 120),
        ("bob@company.com", "alice@company.com", "Sure! What do you need help with?", 115),
        ("alice@company.com", "bob@company.com", "I'm having trouble with the nginx config", 110),
        ("bob@company.com", "alice@company.com", "I'll take a look. Can you share your docker-compose file?", 105),
        ("carol@company.com", "alice@company.com", "Alice, love the new feature! Great work!", 90),
        ("alice@company.com", "carol@company.com", "Thanks Carol! Your designs made it easy", 85),
        ("david@company.com", "alice@company.com", "Can we sync up about the Q1 roadmap?", 60),
        ("emma@company.com", "david@company.com", "David, need the product specs for the blog post", 45),
        ("david@company.com", "emma@company.com", "I'll send them over by EOD", 40),
    ]
    
    for sender_email, receiver_email, body, mins_ago in messages:
        msg_doc = {
            "id": str(uuid.uuid4()),
            "senderId": user_ids[sender_email],
            "receiverId": user_ids[receiver_email],
            "body": body,
            "createdAt": (now - timedelta(minutes=mins_ago)).isoformat()
        }
        await db.messages.insert_one(msg_doc)
    
    print(f"Created {len(messages)} demo messages")
    
    print("=" * 60)
    print("SEED COMPLETE!")
    print("=" * 60)
    print("\nDemo Accounts (all passwords: password123):")
    print("-" * 40)
    for user in DEMO_USERS:
        print(f"  {user['email']}")
    print("-" * 40)
    print("\nYou can now login with any of these accounts.")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(seed_database())
