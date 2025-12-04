from flask import (
    Flask,
    request,
    render_template_string,
    session,
    redirect,
    url_for,
    g,
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import CSRFProtect
import sqlite3
import os


app = Flask(__name__)

# En producción usa una variable de entorno para el SECRET_KEY
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")

# Cookies de sesión más seguras
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = bool(
    os.environ.get("FORCE_HTTPS", False)
)  # True si usas HTTPS
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Protección CSRF
csrf = CSRFProtect(app)



DATABASE = "example.db"


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


@app.teardown_appcontext
def close_connection(exception):
    db = g.pop("_database", None)
    if db is not None:
        db.close()


@app.after_request
def apply_security_headers(response):
    # Mitigaciones para hardening
    response.headers["X-Frame-Options"] = "DENY"  # anti-clickjacking
    response.headers["X-Content-Type-Options"] = "nosniff"  # evitar MIME-sniffing
    # CSP básica
    response.headers[
        "Content-Security-Policy"
    ] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    # Minimizar información del servidor
    response.headers["Server"] = ""
    return response



def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    return check_password_hash(stored_hash, password)



# Página principal
@app.route("/")
def index():
    return render_template_string(
        """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
        <title>Welcome</title>
    </head>
    <body>
        <div class="container">
        <h1 class="mt-5">Welcome to the Example Application!</h1>
        <p class="lead">This is the home page. Please <a href="{{ url_for('login') }}">login</a>.</p>
        </div>
    </body>
    </html>
    """
    )


# Template separado para login (con token CSRF)
login_template = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
    <title>Login</title>
</head>
<body>
    <div class="container">
    <h1 class="mt-5">Login</h1>
    {% if error %}
        <div class="alert alert-danger" role="alert">{{ error }}</div>
    {% endif %}
    <form method="post">
        <!-- token CSRF -->
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
        <div class="form-group">
            <label for="username">Username</label>
            <input required type="text" class="form-control" id="username" name="username">
        </div>
        <div class="form-group">
            <label for="password">Password</label>
            <input required type="password" class="form-control" id="password" name="password">
        </div>
        <button type="submit" class="btn btn-primary">Login</button>
    </form>
    </div>
</body>
</html>
"""


# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Validaciones básicas
        if not username or not password:
            return render_template_string(
                login_template, error="Username and password are required."
            )

        conn = get_db_connection()
        try:
            # Buscar por username solo, luego verificar contraseña
            query = "SELECT * FROM users WHERE username = ?"
            user = conn.execute(query, (username,)).fetchone()
        finally:
            conn.close()

        if user and verify_password(user["password"], password):
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))
        else:
            return render_template_string(login_template, error="Invalid credentials.")
    # GET
    return render_template_string(login_template, error=None)


# Template para dashboard
dashboard_template = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
    <title>Dashboard</title>
</head>
<body>
    <div class="container">
        <h1 class="mt-5">Welcome, user {{ user_id }}!</h1>

    <form action="{{ url_for('submit_comment') }}" method="post">
        <!-- token CSRF -->
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
        <div class="form-group">
            <label for="comment">Comment</label>
            <textarea class="form-control" id="comment" name="comment" rows="3" required></textarea>
        </div>
        <button type="submit" class="btn btn-primary">Submit Comment</button>
    </form>

    <h2 class="mt-5">Your Comments</h2>
    <ul class="list-group">
        {% for comment in comments %}
            <!-- escape para prevenir XSS -->
            <li class="list-group-item">{{ comment['comment'] | e }}</li>
        {% endfor %}
    </ul>
    </div>
</body>
</html>
"""


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    conn = get_db_connection()
    try:
        comments = conn.execute(
            "SELECT comment FROM comments WHERE user_id = ?", (user_id,)
        ).fetchall()
    finally:
        conn.close()

    return render_template_string(
        dashboard_template, user_id=user_id, comments=comments
    )


@app.route("/submit_comment", methods=["POST"])
def submit_comment():
    if "user_id" not in session:
        return redirect(url_for("login"))

    # CSRFProtect valida el token automáticamente
    comment = request.form.get("comment", "").strip()
    user_id = session["user_id"]

    # Validación
    if not comment or len(comment) > 2000:
        return redirect(url_for("dashboard"))

    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO comments (user_id, comment) VALUES (?, ?)",
            (user_id, comment),
        )
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("dashboard"))


# Admin panel
@app.route("/admin")
def admin():
    if "user_id" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))

    return render_template_string(
        """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
        <title>Admin Panel</title>
    </head>
    <body>
        <div class="container">
        <h1 class="mt-5">Welcome to the admin panel!</h1>
        </div>
    </body>
    </html>
    """
    )

@app.route('/testerror')
def testerror():
    return 1 / 0  # fuerza un ZeroDivisionError


if __name__ == "__main__":
    # En producción: debug=False
    app.run(debug=False, host="127.0.0.1", port=5000)