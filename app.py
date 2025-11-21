# app.py
import os
import sqlite3
import hashlib
import uuid
import json
import csv
import io
import http.cookies
from wsgiref.simple_server import make_server
from urllib.parse import parse_qs, unquote_plus

# ---------- Configuration ----------
DB_PATH = 'expenseeye.db'
SQL_FILE = 'database.sql'
SESSION_COOKIE = 'ee_sid'
SESSIONS = {}  # in-memory session store: session_id -> user_id

# ---------- Auto-create DB from SQL if missing ----------
def ensure_db():
    if os.path.exists(DB_PATH):
        return
    if not os.path.exists(SQL_FILE):
        print(f'ERROR: {SQL_FILE} not found. Create database.sql first.')
        exit(1)
    print('Creating database from', SQL_FILE)
    with open(SQL_FILE, 'r', encoding='utf-8') as f:
        script = f.read()
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.executescript(script)
        conn.commit()
    finally:
        conn.close()
    print('Database created:', DB_PATH)

ensure_db()

# ---------- DB helper ----------
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# ---------- Security helpers ----------
def sha256_hash(password, salt):
    return hashlib.sha256((salt + password).encode('utf-8')).hexdigest()

def set_cookie(headers, name, value, max_age=86400):
    cookie = http.cookies.SimpleCookie()
    cookie[name] = value
    cookie[name]['path'] = '/'
    cookie[name]['max-age'] = str(max_age)
    headers.append(('Set-Cookie', cookie.output(header='').strip()))

def clear_cookie(headers, name):
    cookie = http.cookies.SimpleCookie()
    cookie[name] = ''
    cookie[name]['path'] = '/'
    cookie[name]['max-age'] = '0'
    headers.append(('Set-Cookie', cookie.output(header='').strip()))

def get_current_user(environ):
    cookies = http.cookies.SimpleCookie(environ.get('HTTP_COOKIE', ''))
    sid = cookies.get(SESSION_COOKIE)
    if not sid:
        return None
    return SESSIONS.get(sid.value)

# ---------- Request parsing ----------
def parse_post(environ):
    """Parse application/x-www-form-urlencoded POST body and return dict of first values."""
    try:
        length = int(environ.get('CONTENT_LENGTH', 0) or 0)
    except (ValueError, TypeError):
        length = 0
    raw = environ['wsgi.input'].read(length) if length else b''
    decoded = raw.decode('utf-8') if raw else ''
    qs = parse_qs(decoded, keep_blank_values=True)
    # convert to simple dict: key -> first value (URL-decoded)
    return {k: unquote_plus(v[0]) if isinstance(v, list) else v for k, v in qs.items()}

# ---------- Static file serving ----------
def serve_static_file(path):
    # path is relative, e.g. 'index.html' or 'static/style.css'
    if not os.path.exists(path):
        return None, None
    ct = 'text/plain'
    if path.endswith('.html'):
        ct = 'text/html'
    elif path.endswith('.css'):
        ct = 'text/css'
    elif path.endswith('.js'):
        ct = 'application/javascript'
    elif path.endswith('.json'):
        ct = 'application/json'
    elif path.endswith('.png'):
        ct = 'image/png'
    elif path.endswith('.jpg') or path.endswith('.jpeg'):
        ct = 'image/jpeg'
    elif path.endswith('.svg'):
        ct = 'image/svg+xml'
    elif path.endswith('.csv'):
        ct = 'text/csv'
    with open(path, 'rb') as f:
        return f.read(), ct

# ---------- Routes / Handlers ----------
def handle_index(environ, start_response):
    content, ct = serve_static_file('index.html')
    if content is None:
        start_response('500 Internal Server Error', [('Content-Type', 'text/plain')])
        return [b'index.html not found']
    start_response('200 OK', [('Content-Type', ct)])
    return [content]

def handle_static(environ, start_response, relpath):
    # prevent path traversal
    relpath = relpath.lstrip('/')
    # allow only files in project folder (index and any static subfolders)
    content, ct = serve_static_file(relpath)
    if content is None:
        start_response('404 Not Found', [('Content-Type', 'text/plain')])
        return [b'Not found']
    start_response('200 OK', [('Content-Type', ct)])
    return [content]

def handle_register(environ, start_response):
    data = parse_post(environ)
    username = (data.get('username') or '').strip()
    email = (data.get('email') or '').strip()
    password = (data.get('password') or '').strip()
    if not username or not email or not password:
        return redirect('/', start_response)

    salt = uuid.uuid4().hex
    phash = sha256_hash(password, salt)
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute('INSERT INTO users (username, email, password_hash, salt) VALUES (?, ?, ?, ?)',
                    (username, email, phash, salt))
        conn.commit()
    except sqlite3.IntegrityError:
        # username/email exists
        return redirect('/', start_response)
    uid = cur.lastrowid
    sid = str(uuid.uuid4())
    SESSIONS[sid] = uid
    headers = []
    set_cookie(headers, SESSION_COOKIE, sid)
    start_response('302 Found', headers + [('Location', '/')])
    return [b'']

def handle_login(environ, start_response):
    data = parse_post(environ)
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()
    if not username or not password:
        return redirect('/', start_response)
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT id, password_hash, salt FROM users WHERE username = ?', (username,))
    row = cur.fetchone()
    if not row:
        return redirect('/', start_response)
    if sha256_hash(password, row['salt']) == row['password_hash']:
        sid = str(uuid.uuid4())
        SESSIONS[sid] = row['id']
        headers = []
        set_cookie(headers, SESSION_COOKIE, sid)
        start_response('302 Found', headers + [('Location', '/')])
        return [b'']
    return redirect('/', start_response)

def handle_logout(environ, start_response):
    cookies = http.cookies.SimpleCookie(environ.get('HTTP_COOKIE', ''))
    sid = cookies.get(SESSION_COOKIE)
    if sid and sid.value in SESSIONS:
        del SESSIONS[sid.value]
    headers = []
    clear_cookie(headers, SESSION_COOKIE)
    start_response('302 Found', headers + [('Location', '/')])
    return [b'']

def handle_add_expense(environ, start_response):
    uid = get_current_user(environ)
    if not uid:
        return redirect('/', start_response)
    data = parse_post(environ)
    try:
        amount = float(data.get('amount', '0') or '0')
    except ValueError:
        amount = 0.0
    category_id = data.get('category_id')
    try:
        category_id = int(category_id) if category_id else None
    except (ValueError, TypeError):
        category_id = None
    note = data.get('note') or ''
    date = data.get('date') or ''
    conn = get_db()
    cur = conn.cursor()
    cur.execute('INSERT INTO expenses (user_id, amount, category_id, note, date) VALUES (?, ?, ?, ?, ?)',
                (uid, amount, category_id, note, date))
    conn.commit()
    # On success redirect back to root (frontend handles subsequent fetch)
    start_response('302 Found', [('Location', '/')])
    return [b'']

def handle_expenses_json(environ, start_response):
    uid = get_current_user(environ)
    if not uid:
        start_response('401 Unauthorized', [('Content-Type', 'application/json')])
        return [json.dumps({'error': 'unauthorized'}).encode('utf-8')]
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        SELECT e.id, e.amount, e.note, e.date, c.name as category
        FROM expenses e
        LEFT JOIN categories c ON e.category_id = c.id
        WHERE e.user_id = ?
        ORDER BY e.date DESC, e.created_at DESC
        LIMIT 500
    ''', (uid,))
    rows = [dict(r) for r in cur.fetchall()]
    start_response('200 OK', [('Content-Type', 'application/json')])
    return [json.dumps(rows, default=str).encode('utf-8')]

def handle_export_csv(environ, start_response):
    uid = get_current_user(environ)
    if not uid:
        return redirect('/', start_response)
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        SELECT e.id, e.date, c.name as category, e.note, e.amount
        FROM expenses e
        LEFT JOIN categories c ON e.category_id = c.id
        WHERE e.user_id = ?
        ORDER BY e.date DESC
    ''', (uid,))
    rows = cur.fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['id', 'date', 'category', 'note', 'amount'])
    for r in rows:
        writer.writerow([r['id'], r['date'] or '', r['category'] or '', r['note'] or '', r['amount']])
    csv_bytes = output.getvalue().encode('utf-8')
    headers = [
        ('Content-Type', 'text/csv; charset=utf-8'),
        ('Content-Disposition', 'attachment; filename="expenses.csv"'),
        ('Content-Length', str(len(csv_bytes)))
    ]
    start_response('200 OK', headers)
    return [csv_bytes]

# ---------- Utility ----------
def redirect(location, start_response):
    start_response('302 Found', [('Location', location)])
    return [b'']

# ---------- Router ----------
def app(environ, start_response):
    path = environ.get('PATH_INFO', '/') or '/'
    method = environ.get('REQUEST_METHOD', 'GET').upper()

    # Serve root index.html
    if path == '/' and method == 'GET':
        return handle_index(environ, start_response)

    # Static: allow serving files in project root (e.g., images)
    if path.startswith('/static/') or path.endswith('.png') or path.endswith('.jpg') or path.endswith('.jpeg'):
        # Map to local path (strip leading /)
        rel = path.lstrip('/')
        return handle_static(environ, start_response, rel)

    # Auth routes
    if path == '/register' and method == 'POST':
        return handle_register(environ, start_response)
    if path == '/login' and method == 'POST':
        return handle_login(environ, start_response)
    if path == '/logout':
        return handle_logout(environ, start_response)

    # Expense API
    if path == '/add_expense' and method == 'POST':
        return handle_add_expense(environ, start_response)
    if path == '/expenses' and method == 'GET':
        return handle_expenses_json(environ, start_response)
    if path == '/export_csv' and method == 'GET':
        return handle_export_csv(environ, start_response)

    # Fallback
    start_response('404 Not Found', [('Content-Type', 'text/plain')])
    return [b'Not Found']

# ---------- Run server ----------
if __name__ == '__main__':
    port = 8000
    print(f'Starting server on http://127.0.0.1:{port}  (Press CTRL+C to stop)')
    with make_server('', port, app) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print('Server stopped.')
