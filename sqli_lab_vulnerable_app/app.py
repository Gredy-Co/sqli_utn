"""
=============================================================
  SQL INJECTION VULNERABLE LAB  –  ISW-1013 Calidad del Software
  Universidad Técnica Nacional
=============================================================

  ⚠️  ESTE ARCHIVO CONTIENE VULNERABILIDADES INTENCIONALES ⚠️
  Uso exclusivo para laboratorio académico local.
  No exponer a Internet ni usar fuera de entorno controlado.

  Vulnerabilidades presentes (para que los estudiantes las encuentren):
    V-01  SQL Injection en login (concatenación directa)
    V-02  SQL Injection en búsqueda (concatenación directa)
    V-03  Contraseñas en texto plano (sin hashing)
    V-04  SECRET_KEY hardcodeada en el código fuente
    V-05  Modo debug=True activo (expone debugger interactivo)
    V-06  Exposición de la consulta SQL cruda en la interfaz
    V-07  Enlace "Admin" visible para todos los roles en la navegación
    V-08  Sin protección CSRF en formularios
=============================================================
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH  = BASE_DIR / "db" / "lab.db"

app = Flask(__name__)

# ---------------------------------------------------------------
# V-04: SECRET_KEY hardcodeada en el código fuente.
# En una aplicación real debe cargarse desde una variable de
# entorno y nunca commitearse al repositorio.
# ---------------------------------------------------------------
app.config["SECRET_KEY"] = "dev-secret-key-insegura-1234"


# ---------------------------------------------------------------
# Conexión a la base de datos
# ---------------------------------------------------------------
def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------
# Inicialización de la base de datos con datos de prueba
# ---------------------------------------------------------------
def init_db():
    conn = get_connection()
    cur  = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT    NOT NULL UNIQUE,
        password TEXT    NOT NULL,
        role     TEXT    NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS books (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        title    TEXT NOT NULL,
        author   TEXT NOT NULL,
        category TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        event      TEXT NOT NULL,
        username   TEXT,
        detail     TEXT,
        timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # -------------------------------------------------------
    # V-03: Contraseñas almacenadas en TEXTO PLANO.
    # Nunca deben almacenarse así en una aplicación real.
    # Deben usarse bcrypt, Argon2 o PBKDF2.
    # -------------------------------------------------------
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        users = [
            ("admin",   "Admin123",   "admin"),
            ("analyst", "Analyst123", "user"),
            ("student", "Student123", "user"),
        ]
        cur.executemany(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            users
        )

    cur.execute("SELECT COUNT(*) FROM books")
    if cur.fetchone()[0] == 0:
        books = [
            ("Secure Coding Fundamentals",   "J. Howard",    "security"),
            ("Flask Web Patterns",           "A. Miller",    "development"),
            ("Practical SQL",                "A. DeBarros",  "database"),
            ("Threat Modeling Essentials",   "M. Silva",     "security"),
            ("Performance Testing Handbook", "R. Jones",     "qa"),
            ("OWASP Testing Guide",          "OWASP Team",   "security"),
            ("Clean Code",                   "R. Martin",    "development"),
            ("The Web Application Hacker",   "Stuttard",     "security"),
        ]
        cur.executemany(
            "INSERT INTO books (title, author, category) VALUES (?, ?, ?)",
            books
        )

    conn.commit()
    conn.close()


def log_event(event, username=None, detail=None):
    """Registra un evento en el log de auditoría."""
    conn = get_connection()
    conn.execute(
        "INSERT INTO audit_log (event, username, detail) VALUES (?, ?, ?)",
        (event, username, detail)
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------
# Rutas
# ---------------------------------------------------------------

@app.route("/")
def index():
    if session.get("username"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # ---------------------------------------------------
        # V-01 CORREGIDO: Consulta parametrizada con placeholder ?.
        # El input del usuario NUNCA se concatena directamente
        # en el texto de la consulta SQL. SQLite maneja el
        # escapado de forma segura de manera interna.
        # ---------------------------------------------------
        conn = get_connection()
        try:
            user = conn.execute(
                "SELECT id, username, password, role FROM users WHERE username = ?",
                (username,)
            ).fetchone()
        except Exception as e:
            # El error interno NO se expone al usuario final.
            flash("Error al procesar la solicitud. Intente nuevamente.", "error")
            conn.close()
            return render_template("login.html")
        conn.close()

        if user:
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            session["role"]     = user["role"]
            log_event("LOGIN_OK", user["username"])
            flash("Inicio de sesión exitoso.", "success")
            return redirect(url_for("dashboard"))

        log_event("LOGIN_FAIL", username)
        flash("Credenciales incorrectas.", "error")

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if not session.get("username"):
        flash("Debe iniciar sesión primero.", "error")
        return redirect(url_for("login"))
    return render_template(
        "dashboard.html",
        username=session.get("username"),
        role=session.get("role")
    )


@app.route("/search", methods=["GET", "POST"])
def search():
    if not session.get("username"):
        flash("Debe iniciar sesión primero.", "error")
        return redirect(url_for("login"))

    books     = []
    raw_query = None

    if request.method == "POST":
        term = request.form.get("term", "")

        # ---------------------------------------------------
        # V-02: SQL INJECTION EN BÚSQUEDA
        # El término de búsqueda se inserta directamente en
        # la consulta con LIKE.
        #
        # Payload para extraer todos los usuarios:
        #   %' UNION SELECT id, username, password, role FROM users --
        #
        # Payload para verificar número de columnas:
        #   %' UNION SELECT 1,2,3,4 --
        # ---------------------------------------------------
        # V-02: Búsqueda vulnerable también en una sola línea.
        # Payload: %' UNION SELECT id, username, password, role FROM users --
        raw_query = f"SELECT id, title, author, category FROM books WHERE title LIKE '%{term}%' OR author LIKE '%{term}%' OR category LIKE '%{term}%'"

        conn = get_connection()
        try:
            books = conn.execute(raw_query).fetchall()
        except Exception as e:
            flash(f"Error en la base de datos: {e}", "error")
        conn.close()

    # V-06: La consulta SQL cruda se pasa al template y se
    # muestra en pantalla — expone la estructura interna de la BD.
    return render_template("search.html", books=books, raw_query=raw_query)


@app.route("/admin")
def admin():
    if not session.get("username"):
        flash("Debe iniciar sesión primero.", "error")
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        flash("No tiene permisos para acceder al panel de administración.", "error")
        log_event("ACCESS_DENIED", session.get("username"), "Intento de acceso a /admin")
        return redirect(url_for("dashboard"))

    conn  = get_connection()
    users = conn.execute("SELECT id, username, password, role FROM users ORDER BY id").fetchall()
    logs  = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()

    # Nota: se incluye la columna password (texto plano) para que
    # los estudiantes vean claramente la V-03 desde el panel admin.
    return render_template("admin.html", users=users, logs=logs)


@app.route("/logout")
def logout():
    log_event("LOGOUT", session.get("username"))
    session.clear()
    flash("Sesión cerrada.", "success")
    return redirect(url_for("login"))


# ---------------------------------------------------------------
# V-05: debug=True activo.
# En modo debug, Flask activa un debugger interactivo en el
# navegador cuando ocurre un error. Cualquier visitante puede
# ejecutar código Python arbitrario en el servidor.
# Nunca debe usarse debug=True en producción.
# ---------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
