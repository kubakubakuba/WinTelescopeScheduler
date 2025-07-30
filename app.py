from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from flask_login import login_required as flask_login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField, EmailField
from wtforms.validators import InputRequired, Length, ValidationError, Email
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import toml
import os

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'thisisasecretkey'

# Ensure data directory exists
os.makedirs('data', exist_ok=True)

# Data file paths
USERS_FILE = 'data/users.toml'
RESERVATIONS_FILE = 'data/reservations.toml'
CONFIG_FILE = 'config.toml'

# Load configuration
def load_config():
    try:
        with open(CONFIG_FILE, 'r') as f:
            return toml.load(f)
    except FileNotFoundError:
        # Default configuration if file doesn't exist
        return {
            'telescope_schedule': {
                'slot_start_time': '20:00',
                'slot_end_time': '06:00',
                'available_start_times': ['18:00', '19:00', '20:00', '21:00', '22:00', '23:00'],
                'available_end_times': ['04:00', '05:00', '06:00', '07:00', '08:00', '09:00']
            },
            'rdp_config': {
                'server': 'telescope.example.com',
                'port': 3389,
                'username': 'telescope_user',
                'password': 'obs2025!',
                'domain': '',
                'desktop_width': 1920,
                'desktop_height': 1080,
                'color_depth': 32,
                'enable_clipboard': True,
                'enable_audio': True,
                'enable_printers': True
            }
        }

config = load_config()

# Helper functions for date and time management
def generate_date_choices():
    """Generate date choices for the next 30 days"""
    choices = []
    today = datetime.now().date()
    for i in range(31):  # 0 to 30 days (31 total)
        date = today + timedelta(days=i)
        if i == 0:
            label = f"Today ({date.strftime('%B %d')})"
        elif i == 1:
            label = f"Tomorrow ({date.strftime('%B %d')})"
        else:
            label = date.strftime('%B %d, %Y')
        choices.append((date.strftime('%Y-%m-%d'), label))
    return choices

def get_all_users():
    """Get all users for admin dropdown"""
    users = load_users()
    return [(username, f"{data.get('display_name', username)} ({username})") 
            for username, data in users.items()]

def parse_datetime(date_str, time_str):
    """Parse date and time strings into datetime object"""
    return datetime.strptime(f"{date_str} {time_str}", '%Y-%m-%d %H:%M')

def check_reservation_overlap(start_datetime, end_datetime, exclude_id=None):
    """Check if a reservation overlaps with existing reservations"""
    reservations = load_reservations()
    
    for reservation in reservations:
        if exclude_id and reservation['id'] == exclude_id:
            continue
            
        # Parse existing reservation times
        existing_start = parse_datetime(reservation['date'], reservation['start_time'])
        existing_end_date = reservation.get('end_date', reservation['date'])
        existing_end = parse_datetime(existing_end_date, reservation['end_time'])
        
        # Check for overlap: new reservation starts before existing ends AND new reservation ends after existing starts
        if start_datetime < existing_end and end_datetime > existing_start:
            return True, reservation
    
    return False, None

# Initialize data files
def init_data_files():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'w') as f:
            toml.dump({}, f)
    if not os.path.exists(RESERVATIONS_FILE):
        with open(RESERVATIONS_FILE, 'w') as f:
            toml.dump({'reservations': []}, f)

init_data_files()
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, username, email=None, password_hash=None, is_admin=False, must_change_password=False, display_name=None):
        self.id = username  # Use username as ID
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.is_admin = is_admin
        self.must_change_password = must_change_password
        self.display_name = display_name or username  # Fallback to username if no display name

# Data management functions
def load_users():
    with open(USERS_FILE, 'r') as f:
        return toml.load(f)

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        toml.dump(users, f)

def load_reservations():
    with open(RESERVATIONS_FILE, 'r') as f:
        data = toml.load(f)
        return data.get('reservations', [])

def save_reservations(reservations):
    with open(RESERVATIONS_FILE, 'w') as f:
        toml.dump({'reservations': reservations}, f)

def get_user_by_username(username):
    users = load_users()
    if username in users:
        user_data = users[username]
        return User(
            username, 
            user_data.get('email'), 
            user_data.get('password'),
            user_data.get('admin', False),
            user_data.get('must_change_password', False),
            user_data.get('display_name')
        )
    return None

def create_user(username, email, display_name=None, password=None, is_admin=False, must_change_password=True):
    import secrets
    import string
    
    users = load_users()
    if username in users:
        return False  # User already exists
    
    # Generate random password if none provided
    if password is None:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for i in range(12))
    
    users[username] = {
        'email': email,
        'display_name': display_name or username,
        'password': generate_password_hash(password),
        'admin': is_admin,
        'must_change_password': must_change_password,
        'created_at': datetime.utcnow().isoformat()
    }
    save_users(users)
    return password  # Return the generated password

def update_user_password(username, new_password):
    users = load_users()
    if username in users:
        users[username]['password'] = generate_password_hash(new_password)
        users[username]['must_change_password'] = False
        save_users(users)
        return True
    return False

@login_manager.user_loader
def load_user(user_id):
    return get_user_by_username(user_id)

def login_required(f):
    """Custom login_required decorator that also enforces password change requirement"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # First check if user is authenticated (using Flask-Login's logic)
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        
        # Then check if password change is required
        if current_user.must_change_password:
            # Allow access to change-password and logout routes
            if request.endpoint not in ['change_password', 'logout']:
                flash('You must change your password before accessing other features.', 'warning')
                return redirect(url_for('change_password'))
        
        return f(*args, **kwargs)
    return decorated_function

# Reservation management functions
def create_reservation(username, date, start_time, end_time=None, end_date=None, purpose=None):
    """Create a reservation with overlap checking"""
    reservations = load_reservations()
    
    # Use config defaults if end_time/end_date not provided
    if end_time is None:
        end_time = config['telescope_schedule']['slot_end_time']
    if end_date is None:
        # If end time is earlier than start time, it's next day
        start_hour = int(start_time.split(':')[0])
        end_hour = int(end_time.split(':')[0])
        if end_hour < start_hour:
            end_date = (datetime.strptime(date, '%Y-%m-%d') + timedelta(days=1)).strftime('%Y-%m-%d')
        else:
            end_date = date
    
    # Parse start and end datetime
    start_datetime = parse_datetime(date, start_time)
    end_datetime = parse_datetime(end_date, end_time)
    
    # Check for overlaps
    has_overlap, overlapping_reservation = check_reservation_overlap(start_datetime, end_datetime)
    if has_overlap:
        return False, f"Overlaps with existing reservation by {overlapping_reservation['username']}"
    
    reservation = {
        'id': len(reservations) + 1,
        'username': username,
        'date': date,
        'start_time': start_time,
        'end_time': end_time,
        'end_date': end_date,
        'purpose': purpose,
        'created_at': datetime.utcnow().isoformat()
    }
    
    reservations.append(reservation)
    save_reservations(reservations)
    return True, "Reservation created successfully"

def get_user_reservations(username):
    reservations = load_reservations()
    return [r for r in reservations if r['username'] == username]

def cancel_reservation(reservation_id, username):
    reservations = load_reservations()
    for i, reservation in enumerate(reservations):
        if reservation['id'] == reservation_id and reservation['username'] == username:
            del reservations[i]
            save_reservations(reservations)
            return True
    return False

def get_all_reservations():
    return load_reservations()

def get_current_active_reservation(username):
    """Check if user has an active reservation right now"""
    reservations = load_reservations()
    current_time = datetime.now()
    
    for reservation in reservations:
        if reservation['username'] != username:
            continue
            
        # Parse reservation times
        start_datetime = parse_datetime(reservation['date'], reservation['start_time'])
        end_date = reservation.get('end_date', reservation['date'])
        end_datetime = parse_datetime(end_date, reservation['end_time'])
        
        # Check if current time is within the reservation window
        if start_datetime <= current_time <= end_datetime:
            return reservation
    
    return None

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    email = EmailField(validators=[InputRequired(), Email()], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        if get_user_by_username(username.data):
            raise ValidationError('That username already exists. Please choose a different one.')

class CreateUserForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    display_name = StringField(validators=[InputRequired(), Length(min=2, max=50)], render_kw={"placeholder": "Full Name"})
    email = EmailField(validators=[InputRequired(), Email()], render_kw={"placeholder": "Email"})
    is_admin = SelectField('User Type', choices=[('False', 'Regular User'), ('True', 'Administrator')], default='False')
    submit = SubmitField('Create User')

    def validate_username(self, username):
        if get_user_by_username(username.data):
            raise ValidationError('That username already exists. Please choose a different one.')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField(validators=[InputRequired()], render_kw={"placeholder": "Current Password"})
    new_password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "New Password"})
    confirm_password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Confirm New Password"})
    submit = SubmitField('Change Password')

    def validate_confirm_password(self, confirm_password):
        if self.new_password.data != confirm_password.data:
            raise ValidationError('Passwords must match.')

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

class ReservationForm(FlaskForm):
    date = SelectField('Date', validators=[InputRequired()])
    purpose = TextAreaField('Purpose (optional)', render_kw={"placeholder": "Describe your observation plans..."})
    submit = SubmitField('Make Reservation')
    
    def __init__(self, *args, **kwargs):
        super(ReservationForm, self).__init__(*args, **kwargs)
        self.date.choices = generate_date_choices()

class AdminReservationForm(FlaskForm):
    username = SelectField('User', validators=[InputRequired()])
    date = SelectField('Start Date', validators=[InputRequired()])
    start_time = SelectField('Start Time', validators=[InputRequired()])
    end_date = SelectField('End Date', validators=[InputRequired()])
    end_time = SelectField('End Time', validators=[InputRequired()])
    purpose = TextAreaField('Purpose (optional)', render_kw={"placeholder": "Describe the reservation purpose..."})
    submit = SubmitField('Create Reservation')
    
    def __init__(self, *args, **kwargs):
        super(AdminReservationForm, self).__init__(*args, **kwargs)
        self.username.choices = get_all_users()
        self.date.choices = generate_date_choices()
        self.end_date.choices = generate_date_choices()
        
        # Load time choices from config
        config_data = load_config()
        start_times = config_data['telescope_schedule']['available_start_times']
        end_times = config_data['telescope_schedule']['available_end_times']
        
        self.start_time.choices = [(time, time) for time in start_times]
        self.end_time.choices = [(time, time) for time in end_times]

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = get_user_by_username(form.username.data)
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            
            # Check if user must change password
            if user.must_change_password:
                flash('You must change your password before continuing.', 'warning')
                return redirect(url_for('change_password'))
            
            return redirect(url_for('dashboard'))
        flash('Invalid username or password!', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    # Get all reservations to show availability
    reservations = get_all_reservations()
    
    # Format reservations for display
    formatted_reservations = []
    for r in reservations:
        end_date = r.get('end_date', r['date'])
        if end_date != r['date']:
            time_display = f"{r['start_time']} ({r['date']}) - {r['end_time']} ({end_date})"
        else:
            time_display = f"{r['start_time']} - {r['end_time']}"
        
        formatted_reservations.append({
            'username': r['username'],
            'date': r['date'],
            'time_display': time_display,
            'purpose': r.get('purpose', 'No purpose specified')
        })
    
    # Check for current active reservation
    current_reservation = get_current_active_reservation(current_user.username)
    time_remaining = None
    
    if current_reservation:
        # Calculate time remaining in the session
        end_date = current_reservation.get('end_date', current_reservation['date'])
        end_datetime = parse_datetime(end_date, current_reservation['end_time'])
        current_time = datetime.now()
        
        if end_datetime > current_time:
            time_remaining = end_datetime - current_time
        else:
            time_remaining = timedelta(0)  # Session has ended
    
    # Show default slot configuration
    slot_info = {
        'start_time': config['telescope_schedule']['slot_start_time'],
        'end_time': config['telescope_schedule']['slot_end_time']
    }
    
    # Telescope access credentials from config
    telescope_access = {
        'server': config['rdp_config']['server'],
        'username': config['rdp_config']['username'],
        'password': config['rdp_config']['password']
    }
    
    return render_template('dashboard.html', 
                         name=current_user.display_name, 
                         reservations=formatted_reservations,
                         slot_info=slot_info,
                         current_reservation=current_reservation,
                         time_remaining=time_remaining,
                         telescope_access=telescope_access)

@app.route('/make-reservation', methods=['GET', 'POST'])
@login_required
def make_reservation():
    form = ReservationForm()
    if form.validate_on_submit():
        # Use default time slot from config
        start_time = config['telescope_schedule']['slot_start_time']
        
        # Create reservation using the new system
        success, message = create_reservation(
            current_user.username,
            form.date.data,
            start_time,
            purpose=form.purpose.data
        )
        
        if success:
            flash(message, 'success')
            return redirect(url_for('reservations'))
        else:
            flash(f'Reservation failed: {message}', 'danger')
    
    # Show configured time slot info
    start_time = config['telescope_schedule']['slot_start_time']
    end_time = config['telescope_schedule']['slot_end_time']
    
    return render_template('make_reservation.html', 
                         form=form, 
                         slot_info=f"Each reservation is from {start_time} to {end_time} (next day)")

@app.route('/admin-reservation', methods=['GET', 'POST'])
@login_required
def admin_reservation():
    if not current_user.is_admin:
        flash('Access denied. Administrator privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    form = AdminReservationForm()
    if form.validate_on_submit():
        success, message = create_reservation(
            form.username.data,
            form.date.data,
            form.start_time.data,
            form.end_time.data,
            form.end_date.data,
            form.purpose.data
        )
        
        if success:
            flash(message, 'success')
            return redirect(url_for('admin_reservation'))
        else:
            flash(f'Reservation failed: {message}', 'danger')
    
    return render_template('admin_reservation.html', form=form)

@app.route('/create-user', methods=['GET', 'POST'])
@login_required
def create_user_route():
    if not current_user.is_admin:
        flash('Access denied. Administrator privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    form = CreateUserForm()
    if form.validate_on_submit():
        is_admin = form.is_admin.data == 'True'
        generated_password = create_user(
            form.username.data, 
            form.email.data,
            form.display_name.data,
            is_admin=is_admin
        )
        
        if generated_password:
            flash(f'User created successfully! Temporary password: {generated_password}', 'success')
            flash('Please share this password securely with the user. They will be required to change it on first login.', 'info')
            return redirect(url_for('create_user_route'))
        else:
            flash('Username already exists!', 'danger')
    
    return render_template('create_user.html', form=form)

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        user = get_user_by_username(current_user.username)
        if user and check_password_hash(user.password_hash, form.current_password.data):
            success = update_user_password(current_user.username, form.new_password.data)
            if success:
                flash('Password changed successfully!', 'success')
                return redirect(url_for('dashboard'))
        else:
            flash('Current password is incorrect!', 'danger')
    
    return render_template('change_password.html', form=form, must_change=current_user.must_change_password)

@app.route('/reservations')
@login_required
def reservations():
    user_reservations = get_user_reservations(current_user.username)
    return render_template('reservations.html', reservations=user_reservations)

@app.route('/cancel-reservation/<int:reservation_id>', methods=['POST'])
@login_required
def cancel_reservation_route(reservation_id):
    success = cancel_reservation(reservation_id, current_user.username)
    
    if success:
        return jsonify({'success': True, 'message': 'Reservation canceled successfully'})
    else:
        return jsonify({'success': False, 'message': 'Reservation not found or unauthorized'}), 404

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))





if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
