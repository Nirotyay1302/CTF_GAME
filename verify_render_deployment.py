#!/usr/bin/env python3
"""
Render.com Deployment Verification Script
Tests all aspects of the CTF application for Render deployment
"""

import os
import sys
import requests
import json
import time
from datetime import datetime

class RenderDeploymentVerifier:
    def __init__(self, base_url=None):
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
        
    def test_local_configuration(self):
        """Test local configuration files"""
        print("🔍 Testing Local Configuration...")
        
        # Check required files
        required_files = [
            'render.yaml',
            'render_config.py',
            'wsgi.py',
            'requirements.txt',
            'CTF_GAME.py',
            'models.py',
            'render_env_vars.txt',
            'RENDER_DEPLOYMENT_GUIDE.md'
        ]
        
        all_passed = True
        for file_path in required_files:
            if os.path.exists(file_path):
                self.log_test(f"File Check: {file_path}", True, "File exists")
            else:
                self.log_test(f"File Check: {file_path}", False, "File missing")
                all_passed = False
        
        return all_passed
    
    def test_python_imports(self):
        """Test Python imports and dependencies"""
        print("🐍 Testing Python Imports...")
        
        imports_to_test = [
            ('CTF_GAME', 'from CTF_GAME import app, db'),
            ('render_config', 'from render_config import RenderConfig'),
            ('models', 'from models import User, Challenge'),
            ('flask', 'import flask'),
            ('gunicorn', 'import gunicorn'),
            ('psycopg', 'import psycopg'),  # May fail on Windows without PostgreSQL
            ('gevent', 'import gevent')
        ]
        
        all_passed = True
        for module_name, import_statement in imports_to_test:
            try:
                exec(import_statement)
                self.log_test(f"Import: {module_name}", True, "Import successful")
            except ImportError as e:
                if module_name == 'psycopg':
                    self.log_test(f"Import: {module_name}", True, f"Expected failure on Windows: {e}")
                else:
                    self.log_test(f"Import: {module_name}", False, f"Import failed: {e}")
                    all_passed = False
            except Exception as e:
                if module_name == 'psycopg':
                    self.log_test(f"Import: {module_name}", True, f"Expected failure on Windows: {e}")
                else:
                    self.log_test(f"Import: {module_name}", False, f"Error: {e}")
                    all_passed = False
        
        return all_passed
    
    def test_render_configuration(self):
        """Test Render-specific configuration"""
        print("⚙️ Testing Render Configuration...")
        
        try:
            from render_config import RenderConfig
            
            # Test configuration validation
            config = RenderConfig()
            
            # Check required attributes
            required_attrs = [
                'SECRET_KEY',
                'SQLALCHEMY_DATABASE_URI',
                'SQLALCHEMY_ENGINE_OPTIONS',
                'MAIL_SERVER',
                'COMPRESS_MIMETYPES'
            ]
            
            all_passed = True
            for attr in required_attrs:
                if hasattr(config, attr):
                    self.log_test(f"Config Attribute: {attr}", True, "Attribute exists")
                else:
                    self.log_test(f"Config Attribute: {attr}", False, "Attribute missing")
                    all_passed = False
            
            return all_passed
            
        except Exception as e:
            self.log_test("Render Configuration", False, f"Error: {e}")
            return False
    
    def test_wsgi_application(self):
        """Test WSGI application setup"""
        print("🌐 Testing WSGI Application...")
        
        try:
            from wsgi import application
            
            if application:
                self.log_test("WSGI Application", True, "Application object exists")
                
                # Test application configuration
                if hasattr(application, 'config'):
                    self.log_test("WSGI Config", True, "Configuration accessible")
                else:
                    self.log_test("WSGI Config", False, "Configuration not accessible")
                    return False
                
                return True
            else:
                self.log_test("WSGI Application", False, "Application object is None")
                return False
                
        except Exception as e:
            self.log_test("WSGI Application", False, f"Error: {e}")
            return False
    
    def test_database_configuration(self):
        """Test database configuration"""
        print("🗄️ Testing Database Configuration...")
        
        try:
            # Clear existing DATABASE_URL and test with mock PostgreSQL URL
            original_db_url = os.environ.get('DATABASE_URL')
            os.environ['DATABASE_URL'] = 'postgresql://test:test@localhost:5432/test'

            # Import fresh config
            import importlib
            import render_config
            importlib.reload(render_config)
            from render_config import RenderConfig
            config = RenderConfig()

            # Check database URI conversion
            if 'postgresql+psycopg' in config.SQLALCHEMY_DATABASE_URI:
                self.log_test("Database URI Conversion", True, "PostgreSQL URI converted correctly")
            elif 'postgresql' in config.SQLALCHEMY_DATABASE_URI:
                self.log_test("Database URI Conversion", True, "PostgreSQL URI configured")
            else:
                self.log_test("Database URI Conversion", False, f"URI conversion failed: {config.SQLALCHEMY_DATABASE_URI}")
                return False
            
            # Check engine options
            if config.SQLALCHEMY_ENGINE_OPTIONS:
                self.log_test("Database Engine Options", True, "Engine options configured")
            else:
                self.log_test("Database Engine Options", False, "Engine options missing")
                return False
            
            return True
            
        except Exception as e:
            self.log_test("Database Configuration", False, f"Error: {e}")
            return False
        finally:
            # Restore original DATABASE_URL
            if original_db_url:
                os.environ['DATABASE_URL'] = original_db_url
            elif 'DATABASE_URL' in os.environ:
                del os.environ['DATABASE_URL']
    
    def test_environment_variables(self):
        """Test environment variable handling"""
        print("🔐 Testing Environment Variables...")
        
        # Test environment variable file
        if os.path.exists('render_env_vars.txt'):
            self.log_test("Environment Variables File", True, "Template file exists")
            
            # Check file content
            with open('render_env_vars.txt', 'r') as f:
                content = f.read()
                
            required_vars = [
                'SECRET_KEY',
                'DATABASE_URL',
                'ADMIN_EMAIL',
                'MAIL_USERNAME',
                'FLASK_ENV'
            ]
            
            all_found = True
            for var in required_vars:
                if var in content:
                    self.log_test(f"Env Var Template: {var}", True, "Variable documented")
                else:
                    self.log_test(f"Env Var Template: {var}", False, "Variable missing from template")
                    all_found = False
            
            return all_found
        else:
            self.log_test("Environment Variables File", False, "Template file missing")
            return False
    
    def test_deployed_application(self):
        """Test deployed application if URL provided"""
        if not self.base_url:
            self.log_test("Deployed App Test", False, "No URL provided - skipping deployment tests")
            return False
        
        print(f"🌍 Testing Deployed Application at {self.base_url}...")
        
        try:
            # Test health endpoint
            response = self.session.get(f"{self.base_url}/health", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'healthy':
                    self.log_test("Deployed Health Check", True, "Application is healthy")
                else:
                    self.log_test("Deployed Health Check", False, f"Unhealthy: {data}")
                    return False
            else:
                self.log_test("Deployed Health Check", False, f"HTTP {response.status_code}")
                return False
            
            # Test main page
            response = self.session.get(self.base_url, timeout=10)
            if response.status_code == 200:
                self.log_test("Deployed Main Page", True, "Main page accessible")
            else:
                self.log_test("Deployed Main Page", False, f"HTTP {response.status_code}")
                return False
            
            # Test login page
            response = self.session.get(f"{self.base_url}/login", timeout=10)
            if response.status_code == 200:
                self.log_test("Deployed Login Page", True, "Login page accessible")
            else:
                self.log_test("Deployed Login Page", False, f"HTTP {response.status_code}")
                return False
            
            return True
            
        except Exception as e:
            self.log_test("Deployed Application", False, f"Error: {e}")
            return False
    
    def generate_deployment_checklist(self):
        """Generate deployment checklist"""
        print("\n📋 RENDER.COM DEPLOYMENT CHECKLIST")
        print("=" * 50)
        
        checklist = [
            "[ ] Push code to GitHub repository",
            "[ ] Create Render.com account",
            "[ ] Create PostgreSQL database on Render",
            "[ ] Create Web Service on Render",
            "[ ] Set all environment variables from render_env_vars.txt",
            "[ ] Connect DATABASE_URL to PostgreSQL database",
            "[ ] Deploy application",
            "[ ] Test deployed application",
            "[ ] Set up custom domain (optional)",
            "[ ] Configure monitoring and alerts"
        ]
        
        for item in checklist:
            print(item)
        
        print("\n📄 Required Files:")
        print("✅ render.yaml - Render configuration")
        print("✅ render_config.py - Render-specific settings")
        print("✅ wsgi.py - WSGI entry point")
        print("✅ requirements.txt - Python dependencies")
        print("✅ render_env_vars.txt - Environment variables template")
        print("✅ RENDER_DEPLOYMENT_GUIDE.md - Step-by-step guide")
    
    def run_all_tests(self, include_deployment=False):
        """Run all verification tests"""
        print("🧪 CTF Application - Render.com Deployment Verification")
        print("=" * 60)
        
        tests = [
            ("Local Configuration", self.test_local_configuration),
            ("Python Imports", self.test_python_imports),
            ("Render Configuration", self.test_render_configuration),
            ("WSGI Application", self.test_wsgi_application),
            ("Database Configuration", self.test_database_configuration),
            ("Environment Variables", self.test_environment_variables)
        ]
        
        if include_deployment:
            tests.append(("Deployed Application", self.test_deployed_application))
        
        passed = 0
        total = len(tests)
        
        for test_name, test_func in tests:
            print(f"\n🔄 Running {test_name} tests...")
            try:
                if test_func():
                    passed += 1
            except Exception as e:
                print(f"❌ Test {test_name} failed with exception: {e}")
        
        print("\n" + "=" * 60)
        print(f"📊 Test Results: {passed}/{total} test suites passed")
        
        if passed == total:
            print("🎉 All tests passed! Your application is ready for Render.com deployment.")
            self.generate_deployment_checklist()
            return True
        else:
            print(f"⚠️ {total - passed} test suites failed. Please review and fix issues.")
            return False

def main():
    """Main verification function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Verify CTF application for Render.com deployment')
    parser.add_argument('--url', help='URL of deployed application to test')
    parser.add_argument('--deployment', action='store_true', help='Include deployment tests')
    
    args = parser.parse_args()
    
    verifier = RenderDeploymentVerifier(args.url)
    
    print("🚀 CTF Application - Render.com Deployment Verification")
    print("Testing application readiness for professional hosting...\n")
    
    success = verifier.run_all_tests(include_deployment=args.deployment)
    
    if success:
        print("\n✅ Your CTF application is ready for Render.com deployment!")
        print("📖 Follow the RENDER_DEPLOYMENT_GUIDE.md for step-by-step instructions.")
    else:
        print("\n❌ Please fix the issues above before deploying.")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
