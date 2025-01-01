from nicegui import ui
import pyperclip
from datetime import datetime
import json
from pathlib import Path
import re
import string

class VaultPage:
    def __init__(self, password_manager):
        self.pm = password_manager
        self.filter_text = ''
        self.show_deleted = False
        self.current_tab = 'all'
        self.passwords_container = None
        self.title = None
        self.username = None
        self.password = None
        self.url = None
        self.notes = None
        self.last_activity = datetime.now()
        self.clipboard_timer = None
        
    def build(self):
        """Build the vault page UI"""
        with ui.column().classes('w-full h-full'):
            # Header
            with ui.row().classes('w-full items-center justify-between p-4 bg-white shadow-sm'):
                ui.label('Password Vault').classes('text-2xl font-bold')
                
                with ui.row().classes('gap-2'):
                    # Search input
                    self.search_input = ui.input(placeholder='Search passwords...')\
                        .props('outlined dense')\
                        .classes('w-64')\
                        .on('keyup', self.filter_passwords)
                    
                    # Add password button
                    ui.button('Add Password', on_click=self.show_add_dialog)\
                        .props('flat color=primary icon=add')\
                        .classes('font-medium')
                    
                    # Actions row with direct buttons
                    with ui.row().classes('gap-2'):
                        ui.button('Import', icon='upload', on_click=self.show_import_dialog)\
                            .props('flat color=primary dense')\
                            .classes('font-medium')
                        
                        ui.button('Export', icon='download', on_click=self.export_passwords)\
                            .props('flat color=primary dense')\
                            .classes('font-medium')
                        
                        ui.button('Health Check', icon='health_and_safety', on_click=self.show_health_check)\
                            .props('flat color=primary dense')\
                            .classes('font-medium')
                        
                        ui.button('Show Deleted', icon='delete', on_click=self.toggle_deleted)\
                            .props('flat color=primary dense')\
                            .classes('font-medium')
            
            # Password Categories
            with ui.tabs().classes('w-full') as tabs:
                ui.tab('All Passwords', icon='list').classes('cursor-pointer')\
                    .on('click', lambda: self.switch_tab('all'))
                ui.tab('Favorites', icon='star').classes('cursor-pointer')\
                    .on('click', lambda: self.switch_tab('favorites'))
                ui.tab('Recently Added', icon='schedule').classes('cursor-pointer')\
                    .on('click', lambda: self.switch_tab('recent'))
            
            # Passwords List Container
            self.passwords_container = ui.card().classes('w-full p-6 transition-none')
            self.refresh_passwords()

    async def show_dialog_from_menu(self, dialog_func, menu):
        """Helper to show dialog from menu item"""
        menu.close()
        await ui.run_javascript('await new Promise(resolve => setTimeout(resolve, 50))')
        dialog_func()

    def validate_url(self, url: str) -> str:
        """Validate and format URL"""
        if not url:
            return ""
        
        # Add https:// if no protocol specified
        if not re.match(r'^https?://', url):
            url = f'https://{url}'
            
        return url

    def generate_and_set(self):
        generated = self.pm.generate_password()
        self.password.value = generated
        pyperclip.copy(generated)
        ui.notify('Password generated and copied!', type='positive')
        
    def save_password(self):
        if not self.title.value or not self.username.value or not self.password.value:
            ui.notify('Please fill in all required fields', type='warning')
            return
            
        # Validate URL
        url = self.validate_url(self.url.value or '')
            
        if self.pm.add_password(
            self.title.value,
            self.username.value,
            self.password.value,
            url,
            self.notes.value or ''
        ):
            ui.notify('Password saved successfully!', type='positive')
            self.refresh_passwords()
            self.clear_form()
        else:
            ui.notify('Error saving password', type='negative')
    
    def clear_form(self):
        self.title.value = ''
        self.username.value = ''
        self.password.value = ''
        self.url.value = ''
        self.notes.value = ''
            
    def refresh_passwords(self):
        if not self.passwords_container:
            return
            
        self.passwords_container.clear()
        with self.passwords_container:
            passwords = self.pm.get_passwords(include_deleted=self.show_deleted)
            
            # Apply filters
            if self.filter_text:
                passwords = [p for p in passwords if 
                           self.filter_text.lower() in p['title'].lower() or 
                           self.filter_text.lower() in p['username'].lower() or 
                           self.filter_text.lower() in p.get('notes', '').lower()]
            
            # Apply tab filters
            if self.current_tab == 'favorites':
                passwords = [p for p in passwords if p.get('favorite', False)]
            elif self.current_tab == 'recent':
                # Sort by created_at and take top 10
                passwords = sorted(passwords, key=lambda x: x['created_at'], reverse=True)[:10]
            
            if not passwords:
                with ui.column().classes('w-full items-center gap-4 py-8'):
                    ui.label('🔍').classes('text-4xl')
                    ui.label('No passwords found').classes('text-xl text-gray-500')
                    if self.filter_text:
                        ui.label('Try a different search term').classes('text-gray-500')
                    elif self.current_tab == 'favorites':
                        ui.label('Mark some passwords as favorites').classes('text-gray-500')
                    elif self.current_tab == 'recent':
                        ui.label('Add some passwords to see them here').classes('text-gray-500')
                    else:
                        ui.label('Add your first password above').classes('text-gray-500')
                return
            
            with ui.grid(columns=2).classes('w-full gap-4'):
                for entry in passwords:
                    self.build_password_card(entry)

    def switch_tab(self, tab: str):
        """Switch between password tabs"""
        self.current_tab = tab
        self.refresh_passwords()

    def filter_passwords(self, e=None):
        """Filter passwords based on search input"""
        if not self.check_session():
            return
            
        # Sanitize search input
        self.filter_text = re.sub(r'[^a-zA-Z0-9\s]', '', 
            self.search_input.value if self.search_input.value else '')
        self.refresh_passwords()
    
    def logout(self):
        self.pm.logout_user()
        ui.notify('Logged out successfully', type='positive')
        ui.run_javascript('window.location.reload()')
    
    def export_passwords(self):
        """Export passwords with confirmation"""
        if not self.check_session():
            return
            
        dialog = ui.dialog()
        with dialog, ui.card().classes('p-6'):
            ui.label('Export Passwords').classes('text-xl font-bold mb-4')
            ui.label('This will export all your passwords in plain text. '
                    'Make sure to store the file securely.')\
                .classes('text-gray-600 mb-4')
            
            with ui.row().classes('w-full justify-end gap-2'):
                ui.button('Cancel', on_click=dialog.close)\
                    .props('flat')
                ui.button('Export', on_click=lambda: (
                    self.download_export(),
                    dialog.close()
                )).props('color=primary')
        dialog.open()
        
    def download_export(self):
        """Handle actual export"""
        try:
            export_data = self.pm.export_passwords()
            if export_data:
                ui.download(f'passwords_export_{datetime.now().strftime("%Y%m%d")}.json', 
                          export_data)
                ui.notify('Passwords exported successfully!', type='positive')
            else:
                ui.notify('No passwords to export', type='warning')
        except Exception as e:
            ui.notify(f'Error exporting passwords: {str(e)}', type='negative')

    def validate_import_data(self, content: str) -> bool:
        """Validate imported JSON data"""
        try:
            data = json.loads(content)
            if not isinstance(data, dict) or 'passwords' not in data:
                return False
            
            passwords = data['passwords']
            if not isinstance(passwords, list):
                return False
                
            required_fields = {'title', 'username', 'password'}
            for p in passwords:
                if not isinstance(p, dict):
                    return False
                if not all(field in p for field in required_fields):
                    return False
                if not all(isinstance(p[field], str) for field in required_fields):
                    return False
            
            return True
        except:
            return False

    def handle_upload(self, e):
        """Handle file upload with validation"""
        if not self.check_session():
            return
            
        try:
            content = e.content.read()
            if isinstance(content, bytes):
                content = content.decode('utf-8')
                
            if not self.validate_import_data(content):
                ui.notify('Invalid file format', type='negative')
                return
                
            if self.pm.import_passwords(content):
                ui.notify('Passwords imported successfully!', type='positive')
                self.refresh_passwords()
                e.dialog.close()
            else:
                ui.notify('Error importing passwords', type='negative')
        except Exception as ex:
            ui.notify(f'Error: {str(ex)}', type='negative')
    
    def check_session(self):
        """Check session timeout"""
        if (datetime.now() - self.last_activity).total_seconds() > 300:  # 5 minutes
            self.logout()
            return False
        self.last_activity = datetime.now()
        return True
        
    def activity(self):
        """Update last activity time"""
        self.last_activity = datetime.now()

    def copy_to_clipboard(self, text: str):
        """Copy text to clipboard with auto-clear"""
        if not self.check_session():
            return
            
        pyperclip.copy(text)
        ui.notify('Copied to clipboard!', type='positive')
        
        # Clear previous timer if exists
        if self.clipboard_timer:
            self.clipboard_timer.cancel()
        
        # Set timer to clear clipboard after 30 seconds
        async def clear_clipboard():
            await ui.sleep(30)
            pyperclip.copy('')
        self.clipboard_timer = ui.timer(0.1, clear_clipboard, once=True)

    def show_import_dialog(self, menu=None):
        """Show import dialog with proper file handling"""
        if menu:
            menu.close()
        dialog = ui.dialog()
        with dialog, ui.card().classes('p-6'):
            ui.label('Import Passwords').classes('text-xl font-bold mb-4')
            ui.label('Select a JSON file to import').classes('mb-4')
            
            def handle_upload(e):
                self.handle_upload(e)
            
            ui.upload(auto_upload=True, on_upload=handle_upload)\
                .props('accept=.json label="Choose File" flat color=primary')
            
            ui.button('Cancel', on_click=dialog.close).props('flat')
        dialog.open()

    def calculate_password_strength(self, password: str) -> tuple[str, str]:
        """Calculate password strength and return (strength, color)"""
        score = 0
        feedback = []
        
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            feedback.append("Too short")
            
        if any(c.isupper() for c in password):
            score += 1
        else:
            feedback.append("No uppercase")
            
        if any(c.islower() for c in password):
            score += 1
        else:
            feedback.append("No lowercase")
            
        if any(c.isdigit() for c in password):
            score += 1
        else:
            feedback.append("No numbers")
            
        if any(c in string.punctuation for c in password):
            score += 1
        else:
            feedback.append("No special chars")
        
        if score >= 5:
            return "Strong", "text-green-600"
        elif score >= 3:
            return "Medium", "text-orange-500"
        else:
            return "Weak", "text-red-500"

    def show_health_check(self, menu=None):
        """Show password health check dialog"""
        if menu:
            menu.close()
        dialog = ui.dialog()
        with dialog, ui.card().classes('p-6 w-96'):
            ui.label('Password Health Check').classes('text-xl font-bold mb-4')
            
            passwords = self.pm.get_passwords()
            
            total = len(passwords)
            weak = 0
            medium = 0
            strong = 0
            reused = len(passwords) - len(set(p['password'] for p in passwords))
            
            # Calculate password strengths
            for p in passwords:
                strength, _ = self.calculate_password_strength(p['password'])
                if strength == "Weak":
                    weak += 1
                elif strength == "Medium":
                    medium += 1
                else:
                    strong += 1
            
            with ui.column().classes('w-full gap-4'):
                with ui.row().classes('items-center gap-2'):
                    ui.icon('password').classes('text-purple-600')
                    ui.label(f'Total Passwords: {total}').classes('text-lg')
                
                with ui.row().classes('items-center gap-2'):
                    ui.icon('check_circle').classes('text-green-600')
                    ui.label(f'Strong Passwords: {strong}').classes('text-lg text-green-600')
                
                with ui.row().classes('items-center gap-2'):
                    ui.icon('info').classes('text-orange-500')
                    ui.label(f'Medium Passwords: {medium}').classes('text-lg text-orange-500')
                
                with ui.row().classes('items-center gap-2'):
                    ui.icon('warning').classes('text-red-500')
                    ui.label(f'Weak Passwords: {weak}').classes('text-lg text-red-500')
                
                with ui.row().classes('items-center gap-2'):
                    ui.icon('error').classes('text-red-500')
                    ui.label(f'Reused Passwords: {reused}').classes('text-lg text-red-500')
                
                if weak > 0 or reused > 0:
                    ui.label('Recommendations:').classes('text-lg font-bold mt-4')
                    with ui.column().classes('gap-2'):
                        if weak > 0:
                            ui.label('• Use longer passwords (12+ characters)')\
                                .classes('text-sm text-gray-600')
                            ui.label('• Include uppercase, lowercase, numbers, and special characters')\
                                .classes('text-sm text-gray-600')
                        if reused > 0:
                            ui.label('• Avoid reusing passwords across accounts')\
                                .classes('text-sm text-gray-600')
                            ui.label('• Use unique passwords for each account')\
                                .classes('text-sm text-gray-600')
            
            with ui.row().classes('w-full justify-end mt-6'):
                ui.button('Close', on_click=dialog.close).props('flat color=primary')
        dialog.open()

    def build_password_card(self, entry):
        """Build a password card"""
        with ui.card().classes('w-full p-6 transition-none'):
            with ui.column().classes('w-full gap-4'):
                # Header with title and actions
                with ui.row().classes('w-full items-center justify-between'):
                    ui.label(entry['title']).classes('text-lg font-bold text-purple-600')
                    with ui.row().classes('gap-2'):
                        # Favorite button
                        favorite_icon = 'star' if entry.get('favorite', False) else 'star_border'
                        ui.button(icon=favorite_icon, 
                                on_click=lambda e, id=entry['id']: self.toggle_favorite(id))\
                            .props('flat rounded dense').tooltip('Toggle Favorite')
                        
                        # Copy buttons
                        ui.button(icon='person', on_click=lambda: self.copy_to_clipboard(entry['username']))\
                            .props('flat rounded dense').tooltip('Copy Username')
                        ui.button(icon='key', on_click=lambda: self.copy_to_clipboard(entry['password']))\
                            .props('flat rounded dense').tooltip('Copy Password')
                        
                        # Edit and Delete buttons
                        ui.button(icon='edit', on_click=lambda: self.edit_password(entry))\
                            .props('flat rounded dense').tooltip('Edit')
                        ui.button(icon='delete', on_click=lambda: self.delete_password(entry['id']))\
                            .props('flat rounded dense color=negative').tooltip('Delete')
                
                # Password details
                with ui.column().classes('gap-2'):
                    ui.label(f"Username: {entry['username']}")\
                        .classes('text-gray-600')
                    if entry.get('url'):
                        try:
                            ui.link(entry['url'], entry['url'], new_window=True)\
                                .classes('text-purple-600 text-sm')
                        except:
                            ui.label(f"URL: {entry['url']}")\
                                .classes('text-gray-600 text-sm')
                    if entry.get('notes'):
                        ui.label(f"Notes: {entry['notes']}")\
                            .classes('text-sm text-gray-500')
                    
                    # Show password strength and last modified
                    with ui.row().classes('w-full justify-between text-xs text-gray-400 mt-2'):
                        strength, color = self.calculate_password_strength(entry['password'])
                        ui.label(f'Password Strength: {strength}').classes(color)
                        ui.label(f"Modified: {datetime.fromisoformat(entry['modified_at']).strftime('%Y-%m-%d')}")
                    
    def toggle_favorite(self, password_id):
        if self.pm.toggle_favorite(password_id):
            self.refresh_passwords()
    
    def delete_password(self, password_id):
        """Delete a password entry"""
        dialog = ui.dialog()
        with dialog, ui.card().classes('p-6'):
            ui.label('Delete Password').classes('text-xl font-bold mb-4')
            ui.label('Are you sure you want to delete this password?')\
                .classes('text-gray-600 mb-4')
            
            with ui.row().classes('w-full justify-end gap-2'):
                ui.button('Cancel', on_click=dialog.close)\
                    .props('flat')
                ui.button('Delete', on_click=lambda: (
                    self.pm.delete_password(password_id),
                    self.refresh_passwords(),
                    dialog.close(),
                    ui.notify('Password deleted', type='positive')
                )).props('color=negative')
        
        dialog.open()
            
    def edit_password(self, entry, menu=None):
        """Show dialog for editing a password entry"""
        if menu:
            menu.close()
        dialog = ui.dialog()
        with dialog, ui.card().classes('p-6 w-96'):
            ui.label('Edit Password').classes('text-xl font-bold mb-4')
            
            title = ui.input('Title', value=entry['title'])\
                .props('outlined dense').classes('w-full mb-4')
            username = ui.input('Username', value=entry['username'])\
                .props('outlined dense').classes('w-full mb-4')
            password = ui.input('Password', value=entry['password'])\
                .props('outlined dense').classes('w-full mb-4')
            url = ui.input('URL', value=entry.get('url', ''))\
                .props('outlined dense').classes('w-full mb-4')
            notes = ui.input('Notes', value=entry.get('notes', ''))\
                .props('outlined dense').classes('w-full mb-4')
            
            with ui.row().classes('w-full gap-4 justify-end'):
                ui.button('Cancel', on_click=dialog.close)\
                    .props('flat')
                ui.button('Save', on_click=lambda: self.save_edit(
                    entry['id'], title.value, username.value, 
                    password.value, url.value, notes.value, dialog
                )).props('flat color=primary')
        dialog.open()

    def save_edit(self, password_id, title, username, password, url, notes, dialog):
        """Save edited password"""
        # Validate required fields
        if not title or not username or not password:
            ui.notify('Title, username and password are required', type='negative')
            return
            
        # Validate and format URL
        if url and not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
            
        try:
            success = self.pm.edit_password(password_id, {
                'title': title.strip(),
                'username': username.strip(),
                'password': password.strip(),
                'url': url.strip() if url else "",
                'notes': notes.strip() if notes else ""
            })
            
            if success:
                ui.notify('Password updated successfully!', type='positive')
                self.refresh_passwords()
                dialog.close()
            else:
                ui.notify('Failed to update password', type='negative')
        except Exception as e:
            ui.notify(f'Error updating password: {str(e)}', type='negative')
    
    def show_add_dialog(self):
        """Show dialog for adding a new password"""
        with ui.dialog() as self.dialog, ui.card().classes('p-6 w-[500px]'):
            ui.label('Add New Password').classes('text-xl font-bold mb-4')
            
            with ui.column().classes('w-full gap-4'):
                with ui.grid(columns=2).classes('w-full gap-4'):
                    with ui.column().classes('w-full gap-1'):
                        ui.label('Title').classes('text-sm text-gray-600')
                        self.title = ui.input(placeholder='e.g., Gmail Account')\
                            .props('outlined rounded dense').classes('w-full')
                    
                    with ui.column().classes('w-full gap-1'):
                        ui.label('Username').classes('text-sm text-gray-600')
                        self.username = ui.input(placeholder='Enter username or email')\
                            .props('outlined rounded dense').classes('w-full')
                
                with ui.column().classes('w-full gap-1'):
                    ui.label('Password').classes('text-sm text-gray-600')
                    with ui.row().classes('w-full gap-2'):
                        self.password = ui.input(placeholder='Enter or generate password')\
                            .props('outlined rounded dense').classes('flex-grow')
                        ui.button('Generate', icon='casino', on_click=self.show_password_generator)\
                            .props('rounded').classes('bg-purple-600')
                
                with ui.column().classes('w-full gap-1'):
                    ui.label('URL (optional)').classes('text-sm text-gray-600')
                    self.url = ui.input(placeholder='https://')\
                        .props('outlined rounded dense').classes('w-full')
                
                with ui.column().classes('w-full gap-1'):
                    ui.label('Notes (optional)').classes('text-sm text-gray-600')
                    self.notes = ui.input(placeholder='Add any additional notes')\
                        .props('outlined rounded dense').classes('w-full')
                
                with ui.row().classes('w-full gap-4 mt-4'):
                    ui.button('Save', on_click=lambda: (self.save_password(), self.dialog.close()))\
                        .props('unelevated rounded').classes('flex-grow h-10 bg-purple-600')
                    ui.button('Cancel', on_click=lambda: self.dialog.close())\
                        .props('flat rounded').classes('h-10 text-purple-600')
            self.dialog.open()

    def show_password_generator(self):
        """Show password generator dialog with advanced options"""
        dialog = ui.dialog()
        with dialog, ui.card().classes('p-6 w-[500px]'):
            ui.label('Password Generator').classes('text-xl font-bold mb-4')
            
            with ui.column().classes('w-full gap-4'):
                # Password length slider
                length = ui.slider(min=8, max=32, value=16)\
                    .props('label-always')\
                    .classes('w-full')
                ui.label('Password Length').classes('text-sm text-gray-600')
                
                # Character type checkboxes
                with ui.row().classes('w-full gap-4'):
                    with ui.column().classes('flex-1'):
                        upper = ui.checkbox('Uppercase (A-Z)', value=True)\
                            .classes('w-full')
                        lower = ui.checkbox('Lowercase (a-z)', value=True)\
                            .classes('w-full')
                    with ui.column().classes('flex-1'):
                        digits = ui.checkbox('Numbers (0-9)', value=True)\
                            .classes('w-full')
                        special = ui.checkbox('Special (!@#$)', value=True)\
                            .classes('w-full')
                
                # Memorable password option
                memorable = ui.checkbox('Generate Memorable Password')\
                    .classes('w-full')
                
                # Generated password display
                password_display = ui.input('Generated Password')\
                    .props('outlined readonly')\
                    .classes('w-full')
                
                # Password strength meter
                strength_label = ui.label()\
                    .classes('w-full text-center font-bold')
                
                def generate():
                    pwd = self.pm.generate_password(
                        length=length.value,
                        include_upper=upper.value,
                        include_lower=lower.value,
                        include_digits=digits.value,
                        include_special=special.value,
                        memorable=memorable.value
                    )
                    password_display.value = pwd
                    strength, color = self.calculate_password_strength(pwd)
                    strength_label.text = f'Password Strength: {strength}'
                    strength_label.classes(replace=f'w-full text-center font-bold {color}')
                
                # Buttons
                with ui.row().classes('w-full gap-4 justify-between'):
                    ui.button('Generate', on_click=generate)\
                        .props('color=primary')
                    ui.button('Use Password', on_click=lambda: (
                        setattr(self.password, 'value', password_display.value) if hasattr(self, 'password') else None,
                        dialog.close(),
                        ui.notify('Password applied', type='positive')
                    )).props('color=primary')
                    ui.button('Cancel', on_click=dialog.close)\
                        .props('flat')
                
                # Generate initial password
                generate()
        
        dialog.open()

    def toggle_deleted(self):
        self.show_deleted = not self.show_deleted
        self.refresh_passwords()
        status = 'showing' if self.show_deleted else 'hiding'
        ui.notify(f'Now {status} deleted passwords', type='info')
