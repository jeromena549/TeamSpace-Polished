#!/usr/bin/env python3
"""
Backend API Testing for Internal Company Social App
Tests all endpoints: Auth, Users, Messages with demo accounts
"""
import requests
import sys
import json
from datetime import datetime
import time

class CompanySocialAPITester:
    def __init__(self, base_url="https://name-6.preview.emergentagent.com/api"):
        self.base_url = base_url
        self.session = requests.Session()
        self.tests_run = 0
        self.tests_passed = 0
        self.current_user = None
        self.auth_token = None
        self.reset_token = None
        
    def log_test(self, name, status, details=""):
        """Log test result"""
        self.tests_run += 1
        if status:
            self.tests_passed += 1
            print(f"✅ {name}")
        else:
            print(f"❌ {name} - {details}")
            
    def run_test(self, name, method, endpoint, expected_status, data=None, headers=None):
        """Run a single API test"""
        url = f"{self.base_url}/{endpoint}"
        
        # Default headers
        default_headers = {'Content-Type': 'application/json'}
        if headers:
            default_headers.update(headers)
            
        try:
            if method == 'GET':
                response = self.session.get(url, headers=default_headers)
            elif method == 'POST':
                response = self.session.post(url, json=data, headers=default_headers)
            elif method == 'PUT':
                response = self.session.put(url, json=data, headers=default_headers)
            elif method == 'DELETE':
                response = self.session.delete(url, headers=default_headers)
            else:
                self.log_test(name, False, f"Unsupported method: {method}")
                return False, {}

            success = response.status_code == expected_status
            response_data = {}
            
            try:
                response_data = response.json()
            except:
                response_data = {"raw_response": response.text}
                
            if success:
                self.log_test(name, True)
            else:
                self.log_test(name, False, f"Expected {expected_status}, got {response.status_code} - {response_data}")
                
            return success, response_data, response

        except Exception as e:
            self.log_test(name, False, f"Exception: {str(e)}")
            return False, {}, None

    def test_health_endpoints(self):
        """Test health and root endpoints"""
        print("\n🔍 Testing Health Endpoints...")
        
        # Test root
        self.run_test("Root endpoint", "GET", "", 200)
        
        # Test health
        self.run_test("Health check", "GET", "health", 200)

    def test_auth_signup_validation(self):
        """Test signup with invalid company emails"""
        print("\n🔍 Testing Signup Email Validation...")
        
        # Test invalid email domains
        invalid_emails = [
            "test@gmail.com",
            "user@yahoo.com", 
            "admin@example.com"
        ]
        
        for email in invalid_emails:
            success, data, response = self.run_test(
                f"Reject non-company email: {email}",
                "POST", 
                "auth/signup",
                422,  # Validation error
                {
                    "email": email,
                    "password": "password123",
                    "name": "Test User"
                }
            )

    def test_auth_signup_success(self):
        """Test successful signup with company email"""
        print("\n🔍 Testing Successful Signup...")
        
        # Generate unique test user
        timestamp = int(time.time())
        test_email = f"testuser{timestamp}@company.com"
        
        success, data, response = self.run_test(
            "Signup with company email",
            "POST",
            "auth/signup", 
            200,
            {
                "email": test_email,
                "password": "password123",
                "name": "Test User"
            }
        )
        
        if success and data.get('user'):
            print(f"   Created user: {data['user']['email']}")
            return test_email
        return None

    def test_auth_login_demo_accounts(self):
        """Test login with demo accounts"""
        print("\n🔍 Testing Demo Account Logins...")
        
        demo_accounts = [
            "alice@company.com",
            "bob@company.com", 
            "carol@company.com"
        ]
        
        for email in demo_accounts:
            success, data, response = self.run_test(
                f"Login demo account: {email}",
                "POST",
                "auth/login",
                200,
                {
                    "email": email,
                    "password": "password123"
                }
            )
            
            if success and email == "alice@company.com":
                # Save alice's session for further tests
                self.current_user = data.get('user')
                print(f"   Logged in as Alice: {self.current_user}")
                
    def test_auth_invalid_login(self):
        """Test login with invalid credentials"""
        print("\n🔍 Testing Invalid Login...")
        
        # Wrong password
        self.run_test(
            "Login with wrong password",
            "POST",
            "auth/login",
            401,
            {
                "email": "alice@company.com", 
                "password": "wrongpassword"
            }
        )
        
        # Non-existent user
        self.run_test(
            "Login with non-existent user",
            "POST", 
            "auth/login",
            401,
            {
                "email": "nonexistent@company.com",
                "password": "password123"
            }
        )

    def test_protected_endpoints_auth(self):
        """Test protected endpoints require authentication"""
        print("\n🔍 Testing Protected Endpoints Authentication...")
        
        # Clear session to test without auth
        original_cookies = self.session.cookies.copy()
        self.session.cookies.clear()
        
        endpoints_to_test = [
            ("GET", "auth/me", 401),
            ("GET", "users", 401), 
            ("PUT", "users/me", 401),
            ("GET", "messages/conversations", 401)
        ]
        
        for method, endpoint, expected_status in endpoints_to_test:
            self.run_test(
                f"Unauthorized access to {endpoint}",
                method,
                endpoint, 
                expected_status
            )
            
        # Restore session
        self.session.cookies = original_cookies

    def test_user_endpoints(self):
        """Test user-related endpoints"""
        print("\n🔍 Testing User Endpoints...")
        
        # Get current user
        success, data, response = self.run_test(
            "Get current user (/auth/me)",
            "GET",
            "auth/me",
            200
        )
        
        # List all users
        success, data, response = self.run_test(
            "List all users",
            "GET", 
            "users",
            200
        )
        
        if success and isinstance(data, list):
            print(f"   Found {len(data)} users")
            
            # Test get specific user
            if len(data) > 0:
                user_id = data[0]['id']
                self.run_test(
                    f"Get user profile: {user_id}",
                    "GET",
                    f"users/{user_id}",
                    200
                )

        # Test search functionality
        search_terms = ["alice", "engineering", "python"]
        for term in search_terms:
            self.run_test(
                f"Search users: '{term}'",
                "GET",
                f"users?search={term}",
                200
            )

    def test_profile_update(self):
        """Test profile update functionality"""
        print("\n🔍 Testing Profile Update...")
        
        profile_updates = {
            "department": "Engineering", 
            "title": "Senior Developer",
            "skills": ["Python", "FastAPI", "React"],
            "bio": "Backend developer with 5+ years experience",
            "showEmail": True
        }
        
        self.run_test(
            "Update user profile",
            "PUT",
            "users/me",
            200,
            profile_updates
        )

    def test_messaging_endpoints(self):
        """Test messaging functionality"""
        print("\n🔍 Testing Messaging Endpoints...")
        
        # Get conversations list
        success, conversations, response = self.run_test(
            "Get conversations list",
            "GET",
            "messages/conversations", 
            200
        )
        
        # Get all users to find someone to message
        success, users, response = self.run_test(
            "Get users for messaging test",
            "GET",
            "users",
            200
        )
        
        if success and isinstance(users, list) and len(users) > 1:
            # Find a user that's not the current user
            target_user = None
            for user in users:
                if user['id'] != self.current_user.get('id'):
                    target_user = user
                    break
                    
            if target_user:
                user_id = target_user['id']
                
                # Get message thread (might be empty)
                self.run_test(
                    f"Get message thread with {target_user.get('name', 'Unknown')}",
                    "GET",
                    f"messages/thread/{user_id}",
                    200
                )
                
                # Send a test message
                test_message = f"Test message from API test at {datetime.now().strftime('%H:%M:%S')}"
                success, msg_data, response = self.run_test(
                    f"Send message to {target_user.get('name', 'Unknown')}",
                    "POST",
                    f"messages/thread/{user_id}",
                    200,
                    {"body": test_message}
                )
                
                if success:
                    print(f"   Sent message: '{test_message}'")
                    
                    # Get thread again to verify message was added
                    success, thread, response = self.run_test(
                        "Verify message in thread",
                        "GET", 
                        f"messages/thread/{user_id}",
                        200
                    )
                    
                    if success and isinstance(thread, list):
                        print(f"   Thread now has {len(thread)} messages")

    def test_password_reset_flow(self):
        """Test password reset functionality"""
        print("\n🔍 Testing Password Reset Flow...")
        
        # Request password reset for alice
        success, data, response = self.run_test(
            "Request password reset",
            "POST",
            "auth/forgot-password",
            200,
            {"email": "alice@company.com"}
        )
        
        if success:
            # Get reset token from response (homework version returns it)
            reset_token = data.get('token')
            if reset_token:
                print(f"   Got reset token: {reset_token[:20]}...")
                
                # Test password reset with token
                new_password = "newpassword123"
                success, reset_data, response = self.run_test(
                    "Reset password with token",
                    "POST",
                    "auth/reset-password", 
                    200,
                    {
                        "token": reset_token,
                        "newPassword": new_password
                    }
                )
                
                if success:
                    # Try to login with new password
                    self.run_test(
                        "Login with new password",
                        "POST",
                        "auth/login",
                        200,
                        {
                            "email": "alice@company.com",
                            "password": new_password  
                        }
                    )
                    
                    # Reset back to original password for other tests
                    success, data, response = self.run_test(
                        "Request another reset to restore",
                        "POST",
                        "auth/forgot-password",
                        200,
                        {"email": "alice@company.com"}
                    )
                    
                    if success and data.get('token'):
                        self.run_test(
                            "Restore original password",
                            "POST",
                            "auth/reset-password",
                            200,
                            {
                                "token": data['token'],
                                "newPassword": "password123"
                            }
                        )

    def test_error_handling(self):
        """Test error handling for edge cases"""
        print("\n🔍 Testing Error Handling...")
        
        # Test invalid user ID
        self.run_test(
            "Get non-existent user",
            "GET",
            "users/invalid-user-id",
            404
        )
        
        # Test messaging yourself
        if self.current_user:
            self.run_test(
                "Send message to yourself (should fail)",
                "POST",
                f"messages/thread/{self.current_user['id']}",
                400,
                {"body": "Test message"}
            )
        
        # Test empty message body
        success, users, response = self.run_test(
            "Get users for empty message test",
            "GET", 
            "users",
            200
        )
        
        if success and isinstance(users, list) and len(users) > 1:
            target_user = None
            for user in users:
                if user['id'] != self.current_user.get('id'):
                    target_user = user
                    break
            
            if target_user:
                self.run_test(
                    "Send empty message (should fail)",
                    "POST",
                    f"messages/thread/{target_user['id']}",
                    422,  # Validation error
                    {"body": ""}
                )

    def run_all_tests(self):
        """Run complete test suite"""
        print("🚀 Starting Backend API Testing...")
        print(f"Base URL: {self.base_url}")
        print("=" * 60)
        
        # Test sequence
        try:
            self.test_health_endpoints()
            self.test_auth_signup_validation() 
            test_user_email = self.test_auth_signup_success()
            self.test_auth_login_demo_accounts()
            self.test_auth_invalid_login()
            self.test_protected_endpoints_auth()
            self.test_user_endpoints()
            self.test_profile_update()
            self.test_messaging_endpoints()
            self.test_password_reset_flow()
            self.test_error_handling()
            
        except Exception as e:
            print(f"\n❌ Test suite failed with exception: {str(e)}")
            
        # Print summary
        print("\n" + "=" * 60)
        print(f"📊 Test Results: {self.tests_passed}/{self.tests_run} passed")
        success_rate = (self.tests_passed / self.tests_run * 100) if self.tests_run > 0 else 0
        print(f"📈 Success Rate: {success_rate:.1f}%")
        
        if success_rate < 80:
            print("⚠️  Warning: Success rate below 80%")
        elif success_rate >= 95:
            print("🎉 Excellent: Success rate 95%+")
            
        return self.tests_passed, self.tests_run

def main():
    """Main test runner"""
    tester = CompanySocialAPITester()
    passed, total = tester.run_all_tests()
    
    # Return appropriate exit code
    if passed == total:
        return 0
    elif passed / total >= 0.8:  # 80% or better
        return 0  
    else:
        return 1

if __name__ == "__main__":
    sys.exit(main())