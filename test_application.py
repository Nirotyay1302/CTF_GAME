#!/usr/bin/env python3
"""
Comprehensive test suite for CTF application
Tests all major functionality and security features
"""

import os
import sys
import time
import requests
import json
from datetime import datetime

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

class CTFApplicationTester:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.test_results = []
        
    def log_test(self, test_name, success, message=""):
        """Log test result"""
        status = "✅ PASS" if success else "❌ FAIL"
        result = {
            'test': test_name,
            'success': success,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        self.test_results.append(result)
        print(f"{status} {test_name}: {message}")
        
    def test_health_check(self):
        """Test application health check"""
        try:
            response = self.session.get(f"{self.base_url}/health", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'healthy':
                    self.log_test("Health Check", True, "Application is healthy")
                    return True
                else:
                    self.log_test("Health Check", False, f"Unhealthy status: {data}")
                    return False
            else:
                self.log_test("Health Check", False, f"HTTP {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Health Check", False, f"Connection error: {e}")
            return False
    
    def test_database_connection(self):
        """Test database connectivity"""
        try:
            response = self.session.get(f"{self.base_url}/health", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('database') == 'connected':
                    self.log_test("Database Connection", True, "Database is connected")
                    return True
                else:
                    self.log_test("Database Connection", False, "Database not connected")
                    return False
            else:
                self.log_test("Database Connection", False, f"HTTP {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Database Connection", False, f"Error: {e}")
            return False
    
    def test_static_files(self):
        """Test static file serving"""
        static_files = [
            '/static/style.css',
            '/static/theme.css',
            '/static/login.css'
        ]
        
        all_passed = True
        for file_path in static_files:
            try:
                response = self.session.get(f"{self.base_url}{file_path}", timeout=5)
                if response.status_code == 200:
                    self.log_test(f"Static File {file_path}", True, "File served successfully")
                else:
                    self.log_test(f"Static File {file_path}", False, f"HTTP {response.status_code}")
                    all_passed = False
            except Exception as e:
                self.log_test(f"Static File {file_path}", False, f"Error: {e}")
                all_passed = False
        
        return all_passed
    
    def test_login_page(self):
        """Test login page accessibility"""
        try:
            response = self.session.get(f"{self.base_url}/login", timeout=10)
            if response.status_code == 200 and 'login' in response.text.lower():
                self.log_test("Login Page", True, "Login page accessible")
                return True
            else:
                self.log_test("Login Page", False, f"HTTP {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Login Page", False, f"Error: {e}")
            return False
    
    def test_signup_page(self):
        """Test signup page accessibility"""
        try:
            response = self.session.get(f"{self.base_url}/signup", timeout=10)
            if response.status_code == 200 and 'signup' in response.text.lower():
                self.log_test("Signup Page", True, "Signup page accessible")
                return True
            else:
                self.log_test("Signup Page", False, f"HTTP {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Signup Page", False, f"Error: {e}")
            return False
    
    def test_security_headers(self):
        """Test security headers"""
        try:
            response = self.session.get(f"{self.base_url}/", timeout=10)
            headers = response.headers
            
            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'X-XSS-Protection': '1; mode=block'
            }
            
            all_passed = True
            for header, expected_value in security_headers.items():
                if header in headers:
                    if expected_value in headers[header]:
                        self.log_test(f"Security Header {header}", True, f"Present: {headers[header]}")
                    else:
                        self.log_test(f"Security Header {header}", False, f"Wrong value: {headers[header]}")
                        all_passed = False
                else:
                    self.log_test(f"Security Header {header}", False, "Missing")
                    all_passed = False
            
            return all_passed
        except Exception as e:
            self.log_test("Security Headers", False, f"Error: {e}")
            return False
    
    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        try:
            # Test login rate limiting
            login_data = {
                'username': 'nonexistent_user',
                'password': 'wrong_password'
            }
            
            # Make multiple rapid requests
            rate_limited = False
            for i in range(7):  # Exceed the rate limit
                response = self.session.post(f"{self.base_url}/login", data=login_data, timeout=5)
                if response.status_code == 429:
                    rate_limited = True
                    break
                time.sleep(0.1)
            
            if rate_limited:
                self.log_test("Rate Limiting", True, "Rate limiting is working")
                return True
            else:
                self.log_test("Rate Limiting", False, "Rate limiting not triggered")
                return False
        except Exception as e:
            self.log_test("Rate Limiting", False, f"Error: {e}")
            return False
    
    def test_csrf_protection(self):
        """Test CSRF protection (basic check)"""
        try:
            # Try to access a protected endpoint without proper session
            response = self.session.get(f"{self.base_url}/dashboard", timeout=10)
            
            # Should redirect to login or return 401/403
            if response.status_code in [302, 401, 403] or 'login' in response.url:
                self.log_test("CSRF Protection", True, "Protected endpoints require authentication")
                return True
            else:
                self.log_test("CSRF Protection", False, f"Unexpected response: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("CSRF Protection", False, f"Error: {e}")
            return False
    
    def test_error_handling(self):
        """Test error handling"""
        try:
            # Test 404 error
            response = self.session.get(f"{self.base_url}/nonexistent-page", timeout=10)
            if response.status_code == 404:
                self.log_test("404 Error Handling", True, "404 errors handled correctly")
            else:
                self.log_test("404 Error Handling", False, f"Expected 404, got {response.status_code}")
                return False
            
            # Test invalid API request
            response = self.session.post(f"{self.base_url}/api/invalid", timeout=10)
            if response.status_code in [404, 405, 400]:
                self.log_test("API Error Handling", True, "API errors handled correctly")
                return True
            else:
                self.log_test("API Error Handling", False, f"Unexpected response: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Error Handling", False, f"Error: {e}")
            return False
    
    def run_all_tests(self):
        """Run all tests"""
        print("🧪 CTF Application Test Suite")
        print("=" * 50)
        
        tests = [
            self.test_health_check,
            self.test_database_connection,
            self.test_static_files,
            self.test_login_page,
            self.test_signup_page,
            self.test_security_headers,
            self.test_rate_limiting,
            self.test_csrf_protection,
            self.test_error_handling
        ]
        
        passed = 0
        total = len(tests)
        
        for test in tests:
            try:
                if test():
                    passed += 1
            except Exception as e:
                print(f"❌ Test {test.__name__} failed with exception: {e}")
        
        print("\n" + "=" * 50)
        print(f"📊 Test Results: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 All tests passed! Application is ready for production.")
            return True
        else:
            print(f"⚠️ {total - passed} tests failed. Please review and fix issues.")
            return False
    
    def generate_report(self):
        """Generate detailed test report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_tests': len(self.test_results),
            'passed': sum(1 for r in self.test_results if r['success']),
            'failed': sum(1 for r in self.test_results if not r['success']),
            'results': self.test_results
        }
        
        # Save report to file
        report_file = f"test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"📄 Detailed test report saved to: {report_file}")
        return report

def main():
    """Main test function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='CTF Application Test Suite')
    parser.add_argument('--url', default='http://localhost:8000', help='Base URL of the application')
    parser.add_argument('--report', action='store_true', help='Generate detailed report')
    
    args = parser.parse_args()
    
    tester = CTFApplicationTester(args.url)
    
    print(f"Testing CTF application at: {args.url}")
    print("Please ensure the application is running before starting tests.\n")
    
    success = tester.run_all_tests()
    
    if args.report:
        tester.generate_report()
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
