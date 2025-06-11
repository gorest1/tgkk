
import os, secrets
from pathlib import Path
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from tgk_xml_signer import sign_xml, verify_xml_signature

# ------------------------------------------------------------
#  basic configuration
# ------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
KEYS_DIR = BASE_DIR / "keys"
DB_PATH = BASE_DIR / "tgk_signer.db"

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", secrets.token_hex(16)),
    SQLALCHEMY_DATABASE_URI=f"sqlite:///{DB_PATH}",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)

db = SQLAlchemy(app)

# ------------------------------------------------------------
#  database model
# ------------------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(16), nullable=False, default="user")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

# ------------------------------------------------------------
#  one‑time initialisation
# ------------------------------------------------------------
with app.app_context():
    db.create_all()                              # создаёт таблицы при первом запуске
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", role="admin")
        admin.set_password("admin")
        db.session.add(admin)
        db.session.commit()
        if not User.query.filter_by(username="user").first():
            u = User(username="user", role="user")
            u.set_password("user")
            db.session.add(u)
            db.session.commit()

    KEYS_DIR.mkdir(exist_ok=True)

# ------------------------------------------------------------
#  helper functions & decorators
# ------------------------------------------------------------
def current_user():
    """Return current authenticated User or None."""
    if "user_id" in session:
        return db.session.get(User, session["user_id"])
    return None

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not (user and user.role == "admin"):
            flash("Требуются права администратора")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped

# ------------------------------------------------------------
#  routes
# ------------------------------------------------------------

# ---------- registration ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user():
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if User.query.filter_by(username=username).first():
            flash("Логин уже существует")
        else:
            u = User(username=username, role="user")
            u.set_password(password)
            db.session.add(u)
            db.session.commit()
            flash("Аккаунт создан, войдите")
            return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session["user_id"] = user.id
            return redirect(url_for("dashboard"))
        flash("Неверные учетные данные")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user())

# ---------- sign XML ----------
@app.route("/sign", methods=["GET", "POST"])
@login_required
def sign_view():
    if request.method == "POST":
        xml_file = request.files.get("xml_file")
        if not xml_file:
            flash("Не выбран XML файл")
            return redirect(request.url)

        try:
            key_path = next(KEYS_DIR.glob("private_key*.pem"))
            cert_path = next(KEYS_DIR.glob("public_cert*.pem"))
        except StopIteration:
            flash("Ключ или сертификат не найдены")
            return redirect(request.url)

        temp_in = BASE_DIR / "tmp_input.xml"
        temp_out = BASE_DIR / "tmp_signed.xml"
        xml_file.save(temp_in)
        sign_xml(temp_in, key_path, cert_path, xml_output=temp_out)
        return send_file(temp_out, as_attachment=True, download_name="signed.xml")

    return render_template("sign.html", user=current_user())

# ---------- verify XML ----------
@app.route("/verify", methods=["GET", "POST"])
@login_required
def verify_view():
    result = None
    if request.method == "POST":
        xml_file = request.files.get("xml_file")
        if not xml_file:
            flash("Не выбран XML файл")
            return redirect(request.url)

        try:
            cert_path = next(KEYS_DIR.glob("public_cert*.pem"))
        except StopIteration:
            flash("Сертификат не найден")
            return redirect(request.url)

        temp_in = BASE_DIR / "tmp_to_verify.xml"
        xml_file.save(temp_in)
        result = verify_xml_signature(temp_in, cert_path)

    return render_template("verify.html", user=current_user(), result=result)

# ---------- admin: manage keys ----------
@app.route("/admin/keys", methods=["GET", "POST"])
@admin_required
def admin_keys():
    if request.method == "POST":
        key_file = request.files.get("key_file")
        cert_file = request.files.get("cert_file")
        if key_file:
            key_file.save(KEYS_DIR / "private_key.pem")
        if cert_file:
            cert_file.save(KEYS_DIR / "public_cert.pem")
        flash("Файлы сохранены")
        return redirect(request.url)

    files = list(KEYS_DIR.glob("*"))
    return render_template("admin_keys.html", user=current_user(), files=files)

# ------------------------------------------------------------

# ---------- admin: dashboard ----------
@app.route("/admin")
@admin_required
def admin_dashboard():
    return render_template("admin_dashboard.html", user=current_user())

# ---------- admin: users ----------
@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def admin_users():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "add":
            username = request.form.get("new_username")
            password = request.form.get("new_password")
            role = request.form.get("new_role", "user")
            if User.query.filter_by(username=username).first():
                flash("Пользователь уже существует")
            else:
                u = User(username=username, role=role)
                u.set_password(password)
                db.session.add(u)
                db.session.commit()
                flash("Пользователь создан")
        elif action == "reset":
            uid = request.form.get("uid")
            new_pass = request.form.get("new_pass")
            u = db.session.get(User, int(uid))
            if u:
                u.set_password(new_pass)
                db.session.commit()
                flash("Пароль изменён")
    users = User.query.all()
    return render_template("admin_users.html", user=current_user(), users=users)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8000)

# ---------- registration ----------