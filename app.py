from flask import Flask, render_template, request, redirect, send_from_directory, url_for, flash, session
from flask_wtf import FlaskForm
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import os, uuid, bcrypt, sqlite3
from datetime import datetime
from flask_qrcode import QRcode
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user

app = Flask(__name__)
load_dotenv()
app.secret_key = os.getenv('SECRET_KEY', 'vishal007')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB
app.config['PERMANENT_SESSION_LIFETIME'] = 2592000  # 30 days

login_manager = LoginManager(app)
login_manager.login_view = 'login'

QRcode(app)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS files (
        id TEXT PRIMARY KEY,
        name TEXT,
        size REAL,
        downloads INTEGER,
        time TEXT,
        expiry_date TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT,
        role TEXT
    )''')
    conn.commit()
    conn.close()

init_db()

class User(UserMixin):
    def __init__(self, username, role):
        self.id = username
        self.role = role

@login_manager.user_loader
def load_user(username):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT username, role FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    if user:
        return User(user[0], user[1])
    return None

def allowed_file(filename):
    return True  # Allow all file formats

def generate_id():
    return str(uuid.uuid4())[:8]

@app.route('/')
@login_required
def index():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT * FROM files')
    files = [{'id': row[0], 'name': row[1], 'size': row[2], 'downloads': row[3], 'time': row[4]} for row in c.fetchall()]
    conn.close()
    return render_template('index.html', files=files, role=session.get('role'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file selected')
        return redirect('/')
    files = request.files.getlist('file')
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    for file in files:
        if file:
            filename = secure_filename(file.filename)
            file_id = generate_id()
            path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            with open(path, 'wb') as f:
                while True:
                    chunk = file.stream.read(1024 * 1024)  # 1MB chunks
                    if not chunk:
                        break
                    f.write(chunk)
            c.execute('INSERT INTO files (id, name, size, downloads, time) VALUES (?, ?, ?, ?, ?)',
                      (file_id, filename, round(os.path.getsize(path)/1024, 2), 0, datetime.now().strftime('%Y-%m-%d %H:%M')))
    conn.commit()
    conn.close()
    flash('Files uploaded successfully!')
    return redirect('/')

@app.route('/download/<file_id>')
@login_required
def download(file_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT name, downloads FROM files WHERE id = ?', (file_id,))
    file = c.fetchone()
    if file:
        c.execute('UPDATE files SET downloads = downloads + 1 WHERE id = ?', (file_id,))
        conn.commit()
        conn.close()
        return send_from_directory(app.config['UPLOAD_FOLDER'], file[0], as_attachment=True)
    conn.close()
    return 'File not found', 404

@app.route('/delete/<file_id>')
@login_required
def delete(file_id):
    if session.get('role') not in ['admin', 'owner']:
        flash('Unauthorized')
        return redirect('/')
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT name FROM files WHERE id = ?', (file_id,))
    file = c.fetchone()
    if file:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file[0]))
        c.execute('DELETE FROM files WHERE id = ?', (file_id,))
        conn.commit()
        flash('File deleted!')
    conn.close()
    return redirect('/')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT username, password, role FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        if user and user[2] == role and bcrypt.checkpw(password.encode(), user[1].encode()):
            user_obj = User(username, role)
            login_user(user_obj, remember=True)
            session['role'] = role
            return redirect('/')
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('role', None)
    flash('Logged out!')
    return redirect('/login')

@app.route('/qrcode/<file_id>')
@login_required
def qrcode(file_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT name FROM files WHERE id = ?', (file_id,))
    file = c.fetchone()
    conn.close()
    if not file:
        return 'Invalid file ID', 404
    file_url = url_for('download', file_id=file_id, _external=True)
    return render_template('qrcode.html', file_url=file_url)

if __name__ == '__main__':
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)',
              ('vishu', bcrypt.hashpw('vishal007'.encode(), bcrypt.gensalt()).decode(), 'admin'))
    c.execute('INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)',
              ('vishu_owner', bcrypt.hashpw('vishu123'.encode(), bcrypt.gensalt()).decode(), 'owner'))
    c.execute('INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)',
              ('user', bcrypt.hashpw('user'.encode(), bcrypt.gensalt()).decode(), 'user'))
    conn.commit()
    conn.close()
    app.run(debug=False, port=6969, host='0.0.0.0')