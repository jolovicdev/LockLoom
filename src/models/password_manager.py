import json
import bcrypt
import string
import random
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from datetime import datetime

class PasswordManager:
    def __init__(self):
        self.current_user = None
        self.fernet = None
        self.data_dir = Path(__file__).parent.parent.parent / 'data'
        self.data_dir.mkdir(exist_ok=True)
        self.users_file = self.data_dir / 'users.json'
        self.vaults_dir = self.data_dir / 'vaults'
        self.vaults_dir.mkdir(exist_ok=True)
        self.login_attempts = {}  # Track failed login attempts
        self.MAX_IMPORT_SIZE = 10 * 1024 * 1024  # 10MB
        
        # Initialize users file if it doesn't exist
        if not self.users_file.exists():
            with open(self.users_file, 'w') as f:
                json.dump({}, f)

    def _get_vault_path(self, username: str) -> Path:
        return self.vaults_dir / f"{username}.vault"

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def _save_vault(self, data: dict):
        if not self.current_user or not self.fernet:
            raise Exception("Not logged in")
        
        vault_path = self._get_vault_path(self.current_user)
        encrypted_data = self.fernet.encrypt(json.dumps(data).encode())
        with open(vault_path, 'wb') as f:
            f.write(encrypted_data)

    def _load_vault(self) -> dict:
        if not self.current_user or not self.fernet:
            raise Exception("Not logged in")
            
        vault_path = self._get_vault_path(self.current_user)
        if not vault_path.exists():
            return {'passwords': []}
            
        try:
            with open(vault_path, 'rb') as f:
                encrypted_data = f.read()
                
            if not encrypted_data:
                return {'passwords': []}
                
            decrypted_data = self.fernet.decrypt(encrypted_data)
            vault_data = json.loads(decrypted_data.decode())
            if not isinstance(vault_data, dict):
                return {'passwords': []}
            if 'passwords' not in vault_data:
                vault_data['passwords'] = []
            return vault_data
        except Exception as e:
            print(f"Error loading vault: {str(e)}")
            return {'passwords': []}

    def _generate_password_id(self) -> str:
        """Generate a unique password ID"""
        while True:
            new_id = str(random.randint(10000, 99999))
            vault = self._load_vault()
            if not any(p['id'] == new_id for p in vault['passwords']):
                return new_id

    def _check_login_attempts(self, username: str) -> tuple[bool, str]:
        """Check if login is allowed based on previous attempts"""
        current_time = datetime.now()
        if username in self.login_attempts:
            attempts, last_attempt = self.login_attempts[username]
            if attempts >= 3:
                time_diff = (current_time - last_attempt).total_seconds()
                if time_diff < 300:  # 5 minutes lockout
                    return False, f"Account locked. Try again in {5-int(time_diff/60)} minutes"
                else:
                    self.login_attempts[username] = (0, current_time)
        return True, ""

    def _record_login_attempt(self, username: str, success: bool):
        """Record a login attempt"""
        current_time = datetime.now()
        if success:
            if username in self.login_attempts:
                del self.login_attempts[username]
        else:
            attempts = self.login_attempts.get(username, (0, current_time))[0] + 1
            self.login_attempts[username] = (attempts, current_time)

    def _validate_password_strength(self, password: str) -> tuple[bool, str]:
        """Validate password strength during registration"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        if not any(c.isupper() for c in password):
            return False, "Password must contain uppercase letters"
        if not any(c.islower() for c in password):
            return False, "Password must contain lowercase letters"
        if not any(c.isdigit() for c in password):
            return False, "Password must contain numbers"
        if not any(c in string.punctuation for c in password):
            return False, "Password must contain special characters"
        return True, ""

    def register_user(self, username: str, password: str) -> bool:
        if not username or not password:
            return False
            
        # Validate password strength
        valid, message = self._validate_password_strength(password)
        if not valid:
            raise ValueError(message)
            
        with open(self.users_file, 'r') as f:
            users = json.load(f)
            
        if username in users:
            return False
            
        # Generate a fixed salt for this user
        salt = bcrypt.gensalt()
        
        # Generate encryption key and save it
        key = self._derive_key(password, salt)
        
        users[username] = {
            'salt': base64.b64encode(salt).decode(),
            'hashed_password': bcrypt.hashpw(password.encode(), salt).decode(),
            'created_at': datetime.now().isoformat()
        }
        
        with open(self.users_file, 'w') as f:
            json.dump(users, f)
            
        # Initialize empty vault for the user
        self.current_user = username
        self.fernet = Fernet(key)
        self._save_vault({'passwords': []})
        self.logout_user()
            
        return True

    def login_user(self, username: str, password: str) -> bool:
        try:
            if not username or not password:
                return False
                
            # Check login attempts
            allowed, message = self._check_login_attempts(username)
            if not allowed:
                raise Exception(message)
                
            with open(self.users_file, 'r') as f:
                users = json.load(f)
                
            if username not in users:
                self._record_login_attempt(username, False)
                return False
                
            user = users[username]
            salt = base64.b64decode(user['salt'])
            
            # Verify password
            if not bcrypt.checkpw(password.encode(), user['hashed_password'].encode()):
                self._record_login_attempt(username, False)
                return False
            
            # Generate encryption key
            key = self._derive_key(password, salt)
            
            self.current_user = username
            self.fernet = Fernet(key)
            
            # Verify vault can be loaded
            try:
                self._load_vault()
            except Exception as e:
                print(f"Error verifying vault: {str(e)}")
                self._save_vault({'passwords': []})
            
            self._record_login_attempt(username, True)
            return True
        except Exception as e:
            print(f"Login error: {str(e)}")
            return False

    def logout_user(self):
        self.current_user = None
        self.fernet = None

    def add_password(self, title: str, username: str, password: str, url: str = "", notes: str = "") -> bool:
        try:
            vault = self._load_vault()
            
            # Sanitize inputs
            title = title.strip()
            username = username.strip()
            password = password.strip()
            url = url.strip()
            notes = notes.strip()
            
            # Validate required fields
            if not title or not username or not password:
                return False
            
            # Validate URL
            if url and not url.startswith(('http://', 'https://')):
                url = f'https://{url}'
            
            vault['passwords'].append({
                'id': self._generate_password_id(),
                'title': title,
                'username': username,
                'password': password,
                'url': url,
                'notes': notes,
                'favorite': False,
                'created_at': datetime.now().isoformat(),
                'modified_at': datetime.now().isoformat(),
                'deleted': False
            })
            
            self._save_vault(vault)
            return True
        except Exception as e:
            print(f"Error adding password: {str(e)}")
            return False

    def get_passwords(self, include_deleted: bool = False) -> list:
        try:
            vault = self._load_vault()
            passwords = vault.get('passwords', [])
            if not include_deleted:
                passwords = [p for p in passwords if not p.get('deleted', False)]
            return sorted(passwords, key=lambda x: x['modified_at'], reverse=True)
        except Exception as e:
            print(f"Error getting passwords: {str(e)}")
            return []

    def delete_password(self, password_id: str) -> bool:
        """Securely delete a password entry"""
        try:
            vault = self._load_vault()
            for i, password in enumerate(vault['passwords']):
                if password['id'] == password_id:
                    # Overwrite sensitive data with random data before deletion
                    password['username'] = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
                    password['password'] = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
                    password['notes'] = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
                    self._save_vault(vault)
                    
                    # Now mark as deleted
                    password['deleted'] = True
                    password['modified_at'] = datetime.now().isoformat()
                    self._save_vault(vault)
                    return True
            return False
        except Exception as e:
            print(f"Error deleting password: {str(e)}")
            return False

    def toggle_favorite(self, password_id: str) -> bool:
        try:
            vault = self._load_vault()
            for password in vault['passwords']:
                if password['id'] == password_id:
                    password['favorite'] = not password.get('favorite', False)
                    password['modified_at'] = datetime.now().isoformat()
                    self._save_vault(vault)
                    return True
            return False
        except Exception as e:
            print(f"Error toggling favorite: {str(e)}")
            return False

    def export_passwords(self) -> str:
        try:
            vault = self._load_vault()
            export_data = {
                'passwords': [
                    {k: v for k, v in p.items() if k != 'deleted'}
                    for p in vault['passwords']
                    if not p.get('deleted', False)
                ]
            }
            return json.dumps(export_data, indent=2)
        except Exception as e:
            print(f"Error exporting passwords: {str(e)}")
            return ""

    def import_passwords(self, import_data: str) -> bool:
        """Import passwords with size and format validation"""
        try:
            # Check file size
            if len(import_data.encode()) > self.MAX_IMPORT_SIZE:
                raise ValueError("Import file too large")
                
            data = json.loads(import_data)
            if not isinstance(data, dict) or 'passwords' not in data:
                return False
                
            vault = self._load_vault()
            existing_ids = {p['id'] for p in vault['passwords']}
            
            # Import each password with a new unique ID
            for password in data['passwords']:
                if not all(k in password for k in ['title', 'username', 'password']):
                    continue
                    
                # Generate new unique ID
                new_id = self._generate_password_id()
                password['id'] = new_id
                
                # Add missing fields
                password.setdefault('url', '')
                password.setdefault('notes', '')
                password.setdefault('favorite', False)
                password.setdefault('deleted', False)
                password.setdefault('created_at', datetime.now().isoformat())
                password.setdefault('modified_at', datetime.now().isoformat())
                
                vault['passwords'].append(password)
            
            self._save_vault(vault)
            return True
        except Exception as e:
            print(f"Error importing passwords: {str(e)}")
            return False

    def generate_password(self, length=16, include_upper=True, include_lower=True,
                         include_digits=True, include_special=True, memorable=False) -> str:
        """Generate a password with specified requirements.
        
        Args:
            length: Length of the password
            include_upper: Include uppercase letters
            include_lower: Include lowercase letters
            include_digits: Include numbers
            include_special: Include special characters
            memorable: Generate a memorable password instead of a random one
        """
        if memorable:
            # List of common words for memorable passwords
            adjectives = ['Happy', 'Brave', 'Bright', 'Swift', 'Clever', 'Noble']
            nouns = ['Tiger', 'Eagle', 'River', 'Mountain', 'Dragon', 'Phoenix']
            # Generate pattern: Adjective + Noun + Number + Special
            password = (
                random.choice(adjectives) +
                random.choice(nouns) +
                str(random.randint(100, 999)) +
                random.choice('!@#$%^&*')
            )
            return password
            
        # Build character set based on requirements
        chars = ''
        if include_upper:
            chars += string.ascii_uppercase
        if include_lower:
            chars += string.ascii_lowercase
        if include_digits:
            chars += string.digits
        if include_special:
            chars += string.punctuation
            
        if not chars:
            # If no character types selected, use defaults
            chars = string.ascii_letters + string.digits + string.punctuation
            
        while True:
            password = ''.join(random.choice(chars) for _ in range(length))
            # Verify all required character types are present
            if ((not include_upper or any(c.isupper() for c in password)) and
                (not include_lower or any(c.islower() for c in password)) and
                (not include_digits or any(c.isdigit() for c in password)) and
                (not include_special or any(c in string.punctuation for c in password))):
                return password

    def calculate_password_strength(self, password: str) -> str:
        """Calculate password strength.
        
        Returns:
            str: 'Weak', 'Medium', or 'Strong'
        """
        score = 0
        
        # Length
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
            
        # Character types
        if any(c.isupper() for c in password):
            score += 1
        if any(c.islower() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in string.punctuation for c in password):
            score += 1
            
        # Common patterns to avoid
        common_patterns = ['password', '123456', 'qwerty', 'admin']
        if any(pattern in password.lower() for pattern in common_patterns):
            score -= 2
            
        # Determine strength
        if score <= 2:
            return 'Weak'
        elif score <= 4:
            return 'Medium'
        else:
            return 'Strong'

    def edit_password(self, password_id: str, new_data: dict) -> bool:
        """Edit an existing password entry."""
        try:
            if not self.current_user or not self.fernet:
                raise Exception("Not logged in")
                
            if not password_id or not new_data:
                return False
                
            # Sanitize input data
            sanitized_data = {}
            for key, value in new_data.items():
                if isinstance(value, str):
                    sanitized_data[key] = value.strip()
                else:
                    sanitized_data[key] = value
            
            # Validate URL
            if 'url' in sanitized_data and sanitized_data['url']:
                url = sanitized_data['url']
                if not url.startswith(('http://', 'https://')):
                    sanitized_data['url'] = f'https://{url}'
            
            vault = self._load_vault()
            found = False
            
            for password in vault['passwords']:
                if password['id'] == password_id:
                    # Don't edit deleted passwords
                    if password.get('deleted', False):
                        return False
                        
                    # Update fields
                    password.update(sanitized_data)
                    password['modified_at'] = datetime.now().isoformat()
                    found = True
                    break
                    
            if not found:
                return False
                
            self._save_vault(vault)
            return True
            
        except Exception as e:
            print(f"Error editing password: {str(e)}")
            return False
