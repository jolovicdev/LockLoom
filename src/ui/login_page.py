from nicegui import ui
import time

class LoginPage:
    def __init__(self, password_manager, on_login_success):
        self.pm = password_manager
        self.on_login_success = on_login_success
        self.username = None
        self.password = None
        self.page_content = None
        self.login_attempts = {}  # Track failed login attempts
        
    def validate_username(self, username: str) -> tuple[bool, str]:
        """Validate username format."""
        if not username:
            return False, "Username is required"
        if len(username) < 3:
            return False, "Username must be at least 3 characters"
        if len(username) > 30:
            return False, "Username must be less than 30 characters"
        if not username.isalnum():
            return False, "Username can only contain letters and numbers"
        return True, ""
        
    def validate_password(self, password: str) -> tuple[bool, str]:
        """Validate password strength."""
        if not password:
            return False, "Password is required"
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one number"
        if not any(c in '!@#$%^&*()' for c in password):
            return False, "Password must contain at least one special character"
        return True, ""

    def build(self):
        self.page_content = ui.card().classes('w-[400px] p-8 shadow-lg')
        with self.page_content:
            with ui.column().classes('w-full items-center gap-6'):
                # Logo and Title
                ui.label('🔒').classes('text-5xl')
                with ui.column().classes('items-center gap-1'):
                    ui.label('Lock Loom').classes('text-3xl font-bold text-purple-600')
                    ui.label('Secure Password Manager').classes('text-lg text-gray-500')
                
                # Login Form
                with ui.column().classes('w-full gap-4'):
                    with ui.column().classes('w-full gap-1'):
                        ui.label('Username').classes('text-sm text-gray-600')
                        self.username = ui.input(placeholder='Enter your username')\
                            .props('outlined rounded dense').classes('w-full')\
                            .on('keydown.enter', self.try_login)
                    
                    with ui.column().classes('w-full gap-1'):
                        ui.label('Password').classes('text-sm text-gray-600')
                        self.password = ui.input(placeholder='Enter your password', password=True)\
                            .props('outlined rounded dense').classes('w-full')\
                            .on('keydown.enter', self.try_login)
                    
                    with ui.column().classes('w-full gap-2 mt-2'):
                        ui.button('Login', on_click=self.try_login)\
                            .props('unelevated rounded').classes('w-full h-10 bg-purple-600')
                        ui.button('Register', on_click=self.try_register)\
                            .props('flat rounded').classes('w-full h-10 text-purple-600')

    def try_login(self):
        username = self.username.value.strip() if self.username.value else ""
        password = self.password.value if self.password.value else ""
        
        # Check rate limiting
        if username in self.login_attempts:
            attempts, last_attempt = self.login_attempts[username]
            if attempts >= 3:
                time_diff = (time.time() - last_attempt)
                if time_diff < 300:  # 5 minutes lockout
                    ui.notify(f'Account locked. Try again in {5-int(time_diff/60)} minutes', 
                            type='negative')
                    return
                else:
                    self.login_attempts[username] = (0, time.time())
        
        # Validate input
        if not username or not password:
            ui.notify('Please enter both username and password', type='warning')
            return
            
        if self.pm.login_user(username, password):
            ui.notify('Login successful!', type='positive')
            if username in self.login_attempts:
                del self.login_attempts[username]
            self.page_content.clear()
            self.on_login_success()
        else:
            # Track failed attempt
            attempts = self.login_attempts.get(username, (0, time.time()))[0] + 1
            self.login_attempts[username] = (attempts, time.time())
            
            ui.notify('Invalid credentials!', type='negative')
            self.password.value = ''  # Clear password on failed login
    
    def try_register(self):
        username = self.username.value.strip() if self.username.value else ""
        password = self.password.value if self.password.value else ""
        
        # Validate username
        valid, message = self.validate_username(username)
        if not valid:
            ui.notify(message, type='warning')
            return
            
        # Validate password
        valid, message = self.validate_password(password)
        if not valid:
            ui.notify(message, type='warning')
            return
            
        if self.pm.register_user(username, password):
            ui.notify('Registration successful! You can now login.', type='positive')
            self.username.value = ''
            self.password.value = ''
        else:
            ui.notify('Username already exists!', type='negative')
            self.username.value = ''  # Clear username on failed registration
