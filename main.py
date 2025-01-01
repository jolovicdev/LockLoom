from nicegui import ui, app
from pathlib import Path
import os
import sys
import signal
import atexit
# Create project structure
project_root = Path(__file__).parent
src_dir = project_root / 'src'
models_dir = src_dir / 'models'
ui_dir = src_dir / 'ui'
data_dir = project_root / 'data'

# Create directories if they don't exist
for dir_path in [src_dir, models_dir, ui_dir, data_dir]:
    dir_path.mkdir(exist_ok=True)

# Import after ensuring directories exist
from src.models.password_manager import PasswordManager
from src.ui.login_page import LoginPage
from src.ui.vault_page import VaultPage

# Initialize Password Manager
pm = PasswordManager()

def cleanup_and_exit(*args):
    """Clean up and exit the application"""
    print("Cleaning up and exiting...")
    try:
        app.shutdown()
    except:
        pass
    finally:
        os._exit(0)

# Register cleanup handlers
atexit.register(cleanup_and_exit)
signal.signal(signal.SIGINT, cleanup_and_exit)
signal.signal(signal.SIGTERM, cleanup_and_exit)

# Configure app
app.native.window_args['resizable'] = True
app.native.window_args['min_size'] = (1024, 768)
app.native.start_args['debug'] = False

@ui.page('/')
def main_page():
    # Add close button handler
    ui.add_head_html('''
        <script>
            window.onbeforeunload = function() {
                fetch('/shutdown', { method: 'POST' });
            };
        </script>
    ''')
    
    # Set the color theme
    ui.colors(primary='#7C3AED')
    
    # Add custom styles
    ui.add_head_html('''
        <style>
            body {
                background: linear-gradient(135deg, #f5f7ff 0%, #ffffff 100%);
            }
            .q-card {
                border-radius: 16px;
            }
            .q-input {
                border-radius: 12px;
            }
            .q-btn {
                border-radius: 12px;
                font-weight: 600;
                text-transform: none;
                letter-spacing: 0.5px;
            }
            .q-btn:hover {
                transform: translateY(-1px);
            }
            /* Remove focus styles */
            .q-focus-helper {
                display: none !important;
            }
            /* Remove hover effects */
            .q-card:hover {
                transform: none !important;
                box-shadow: none !important;
            }
            /* Fix menu item click area */
            .q-menu {
                min-width: 200px;
            }
            .q-item {
                cursor: pointer;
                padding: 12px 16px;
            }
            .q-item:hover {
                background: rgba(0,0,0,0.05);
            }
        </style>
    ''')
    
    # Create main container
    main_container = ui.element('div').classes('w-full h-full flex items-center justify-center')
    
    def on_login_success():
        main_container.clear()
        with main_container:
            vault_page = VaultPage(pm)
            vault_page.build()
    
    # Create and build the login page
    with main_container:
        login_page = LoginPage(pm, on_login_success)
        login_page.build()

# Add shutdown endpoint
@app.post('/shutdown')
def shutdown():
    cleanup_and_exit()

if __name__ == '__main__':
    try:
        # Run as a native desktop application
        ui.run(
            title='LockLoom Password Manager',
            native=True,
            window_size=(1024, 768),
            fullscreen=False,
            reload=False,
            show=True,
            port=0,
            storage_secret='lockloom_secret',  # Add secret for session storage
        )
    except Exception as e:
        print(f"Error starting application: {str(e)}")
        cleanup_and_exit()
