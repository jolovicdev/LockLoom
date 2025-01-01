import unittest
from src.models.password_manager import PasswordManager
import json
from pathlib import Path
import os
import shutil
import string

class TestPasswordManager(unittest.TestCase):
    def setUp(self):
        """Set up test environment before each test"""
        self.test_dir = Path('test_data')
        self.test_dir.mkdir(exist_ok=True)
        
        # Create test instance with test directory
        self.pm = PasswordManager()
        self.pm.data_dir = self.test_dir
        self.pm.users_file = self.test_dir / 'users.json'
        self.pm.vaults_dir = self.test_dir / 'vaults'
        self.pm.vaults_dir.mkdir(exist_ok=True)
        
        # Initialize empty users file
        with open(self.pm.users_file, 'w') as f:
            json.dump({}, f)
            
        # Strong test password that meets all requirements
        self.test_password = 'TestPass123!'

    def tearDown(self):
        """Clean up test environment after each test"""
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)

    def test_register_user(self):
        """Test user registration"""
        # Test successful registration
        self.assertTrue(self.pm.register_user('testuser', self.test_password))
        
        # Verify user file was created
        with open(self.pm.users_file, 'r') as f:
            users = json.load(f)
        self.assertIn('testuser', users)
        
        # Test duplicate registration
        self.assertFalse(self.pm.register_user('testuser', self.test_password))
        
        # Test invalid inputs
        self.assertFalse(self.pm.register_user('', self.test_password))
        self.assertFalse(self.pm.register_user('testuser', ''))
        
        # Test weak passwords
        with self.assertRaises(ValueError):
            self.pm.register_user('newuser', 'short')  # Too short
        with self.assertRaises(ValueError):
            self.pm.register_user('newuser', 'password123')  # No uppercase
        with self.assertRaises(ValueError):
            self.pm.register_user('newuser', 'PASSWORD123')  # No lowercase
        with self.assertRaises(ValueError):
            self.pm.register_user('newuser', 'Password')  # No numbers
        with self.assertRaises(ValueError):
            self.pm.register_user('newuser', 'Password123')  # No special chars

    def test_login_user(self):
        """Test user login"""
        # Register a test user first
        self.pm.register_user('testuser', self.test_password)
        
        # Test successful login
        self.assertTrue(self.pm.login_user('testuser', self.test_password))
        self.assertEqual(self.pm.current_user, 'testuser')
        
        # Test wrong password
        self.assertFalse(self.pm.login_user('testuser', 'wrongpass'))
        
        # Test non-existent user
        self.assertFalse(self.pm.login_user('nonexistent', self.test_password))
        
        # Test invalid inputs
        self.assertFalse(self.pm.login_user('', self.test_password))
        self.assertFalse(self.pm.login_user('testuser', ''))
        
        # Test rate limiting
        for _ in range(3):
            self.pm.login_user('testuser', 'wrongpass')
        self.assertFalse(self.pm.login_user('testuser', self.test_password))

    def test_password_persistence(self):
        """Test password persistence between sessions"""
        # Register and login
        self.pm.register_user('testuser', self.test_password)
        self.pm.login_user('testuser', self.test_password)
        
        # Add a password
        self.assertTrue(self.pm.add_password(
            'Test Site',
            'username',
            'StrongP@ss123',
            'https://test.com',
            'test notes'
        ))
        
        # Logout and create new instance
        self.pm.logout_user()
        new_pm = PasswordManager()
        new_pm.data_dir = self.test_dir
        new_pm.users_file = self.test_dir / 'users.json'
        new_pm.vaults_dir = self.test_dir / 'vaults'
        
        # Login and verify password exists
        self.assertTrue(new_pm.login_user('testuser', self.test_password))
        passwords = new_pm.get_passwords()
        self.assertEqual(len(passwords), 1)
        self.assertEqual(passwords[0]['title'], 'Test Site')

    def test_password_operations(self):
        """Test password CRUD operations"""
        # Setup
        self.pm.register_user('testuser', self.test_password)
        self.pm.login_user('testuser', self.test_password)
        
        # Test add password
        self.assertTrue(self.pm.add_password('Test', 'user', 'StrongP@ss123'))
        passwords = self.pm.get_passwords()
        self.assertEqual(len(passwords), 1)
        
        # Test favorite
        password_id = passwords[0]['id']
        self.assertTrue(self.pm.toggle_favorite(password_id))
        passwords = self.pm.get_passwords()
        self.assertTrue(passwords[0]['favorite'])
        
        # Test delete
        self.assertTrue(self.pm.delete_password(password_id))
        passwords = self.pm.get_passwords()
        self.assertEqual(len(passwords), 0)
        
        # Test with deleted included
        passwords = self.pm.get_passwords(include_deleted=True)
        self.assertEqual(len(passwords), 1)
        self.assertTrue(passwords[0]['deleted'])

    def test_url_handling(self):
        """Test URL handling in passwords"""
        # Setup
        self.pm.register_user('testuser', self.test_password)
        self.pm.login_user('testuser', self.test_password)
        
        # Test with full URL
        self.assertTrue(self.pm.add_password(
            'Test', 'user', 'StrongP@ss123', 
            'https://test.com'
        ))
        
        # Test with partial URL
        self.assertTrue(self.pm.add_password(
            'Test2', 'user2', 'StrongP@ss123', 
            'test2.com'
        ))
        
        passwords = self.pm.get_passwords()
        self.assertEqual(len(passwords), 2)
        urls = [p['url'] for p in passwords]
        self.assertIn('https://test.com', urls)
        self.assertIn('https://test2.com', urls)

    def test_export_import(self):
        """Test password export and import"""
        # Setup
        self.pm.register_user('testuser', self.test_password)
        self.pm.login_user('testuser', self.test_password)
        
        # Add some test passwords
        self.pm.add_password('Test1', 'user1', 'StrongP@ss123')
        self.pm.add_password('Test2', 'user2', 'StrongP@ss456')
        
        # Export
        export_data = self.pm.export_passwords()
        self.assertIsInstance(export_data, str)
        
        # Clear passwords
        for p in self.pm.get_passwords():
            self.pm.delete_password(p['id'])
        
        # Import
        self.assertTrue(self.pm.import_passwords(export_data))
        
        # Verify
        passwords = self.pm.get_passwords()
        self.assertEqual(len(passwords), 2)
        titles = [p['title'] for p in passwords]
        self.assertIn('Test1', titles)
        self.assertIn('Test2', titles)

    def test_edit_password(self):
        """Test password editing functionality"""
        # Setup
        self.pm.register_user('testuser', self.test_password)
        self.pm.login_user('testuser', self.test_password)
        
        # Add a test password
        self.assertTrue(self.pm.add_password('Test', 'user', 'StrongP@ss123', 'test.com', 'notes'))
        password = self.pm.get_passwords()[0]
        
        # Test successful edit
        new_data = {
            'title': 'Updated Test',
            'username': 'newuser',
            'password': 'StrongP@ss456',
            'url': 'https://newtest.com',
            'notes': 'new notes'
        }
        self.assertTrue(self.pm.edit_password(password['id'], new_data))
        
        # Verify changes
        updated = self.pm.get_passwords()[0]
        for key, value in new_data.items():
            self.assertEqual(updated[key], value)
        
        # Test editing non-existent password
        self.assertFalse(self.pm.edit_password('nonexistent', new_data))
        
        # Test editing deleted password
        self.pm.delete_password(password['id'])
        self.assertFalse(self.pm.edit_password(password['id'], new_data))
        
        # Test with invalid data
        self.assertFalse(self.pm.edit_password(password['id'], {}))
        
        # Test without login
        self.pm.logout_user()
        self.assertFalse(self.pm.edit_password(password['id'], new_data))

    def test_password_generator(self):
        """Test password generation with various options"""
        self.pm.register_user('testuser', self.test_password)
        self.pm.login_user('testuser', self.test_password)
        
        # Test default generation
        pwd = self.pm.generate_password()
        self.assertEqual(len(pwd), 16)
        self.assertTrue(any(c.isupper() for c in pwd))
        self.assertTrue(any(c.islower() for c in pwd))
        self.assertTrue(any(c.isdigit() for c in pwd))
        self.assertTrue(any(c in string.punctuation for c in pwd))
        
        # Test custom length
        pwd = self.pm.generate_password(length=24)
        self.assertEqual(len(pwd), 24)
        
        # Test without uppercase
        pwd = self.pm.generate_password(include_upper=False)
        self.assertFalse(any(c.isupper() for c in pwd))
        
        # Test without lowercase
        pwd = self.pm.generate_password(include_lower=False)
        self.assertFalse(any(c.islower() for c in pwd))
        
        # Test without digits
        pwd = self.pm.generate_password(include_digits=False)
        self.assertFalse(any(c.isdigit() for c in pwd))
        
        # Test without special chars
        pwd = self.pm.generate_password(include_special=False)
        self.assertFalse(any(c in string.punctuation for c in pwd))
        
        # Test memorable password
        pwd = self.pm.generate_password(memorable=True)
        self.assertTrue(any(c.isupper() for c in pwd))
        self.assertTrue(any(c.islower() for c in pwd))
        self.assertTrue(any(c.isdigit() for c in pwd))
        self.assertTrue(any(c in string.punctuation for c in pwd))
        
        # Test with all options disabled
        pwd = self.pm.generate_password(
            include_upper=False,
            include_lower=False,
            include_digits=False,
            include_special=False
        )
        self.assertTrue(len(pwd) > 0)  # Should use defaults

    def test_password_validation(self):
        """Test password validation and sanitization"""
        self.pm.register_user('testuser', self.test_password)
        self.pm.login_user('testuser', self.test_password)
        
        # Test with whitespace
        self.assertTrue(self.pm.add_password(
            ' Test Title ',  # Leading/trailing spaces
            ' username ',
            ' password ',
            ' test.com ',
            ' notes '
        ))
        
        password = self.pm.get_passwords()[0]
        self.assertEqual(password['title'], 'Test Title')  # Should be trimmed
        self.assertEqual(password['username'], 'username')
        self.assertEqual(password['password'], 'password')
        self.assertEqual(password['url'], 'https://test.com')
        self.assertEqual(password['notes'], 'notes')
        
        # Test URL formatting
        self.assertTrue(self.pm.add_password(
            'URL Test',
            'user',
            'pass',
            'http://existing.com'  # Existing protocol
        ))
        password = self.pm.get_passwords()[0]
        self.assertEqual(password['url'], 'http://existing.com')

    def test_password_strength(self):
        """Test password strength calculation"""
        self.pm.register_user('testuser', self.test_password)
        self.pm.login_user('testuser', self.test_password)
        
        # Test weak password
        self.assertTrue(self.pm.add_password(
            'Weak',
            'user',
            'password123'  # Common password
        ))
        
        # Test medium password
        self.assertTrue(self.pm.add_password(
            'Medium',
            'user',
            'Password123!'  # Mixed case, number, symbol
        ))
        
        # Test strong password
        self.assertTrue(self.pm.add_password(
            'Strong',
            'user',
            'xK9#mP2$vL5@nQ8'  # Long, mixed, numbers, symbols
        ))
        
        # Test password reuse
        self.assertTrue(self.pm.add_password(
            'Reused',
            'user2',
            'Password123!'  # Reused password
        ))
        
        # Get all passwords and check strengths
        passwords = self.pm.get_passwords()
        self.assertEqual(len(passwords), 4)
        
        # Count passwords by strength
        strengths = [self.pm.calculate_password_strength(p['password']) 
                    for p in passwords]
        weak = sum(1 for s in strengths if s == 'Weak')
        medium = sum(1 for s in strengths if s == 'Medium')
        strong = sum(1 for s in strengths if s == 'Strong')
        reused = sum(1 for p1 in passwords for p2 in passwords 
                    if p1['id'] != p2['id'] and 
                    p1['password'] == p2['password'])
        
        self.assertEqual(weak, 1)  # One weak password
        self.assertEqual(medium, 2)  # Two medium passwords (including reused)
        self.assertEqual(strong, 1)  # One strong password
        self.assertEqual(reused, 2)  # Two instances of the reused password

if __name__ == '__main__':
    unittest.main()
