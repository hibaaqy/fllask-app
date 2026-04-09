import os
import secrets
import uuid
from datetime import datetime, timedelta
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename

from forms import ContactForm, FileUploadForm, LoginForm, RegistrationForm, StudentForm


load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf"}
ALLOWED_MIME_TYPES = {"image/png", "image/jpeg", "application/pdf"}
MAX_UPLOAD_SIZE = 2 * 1024 * 1024

os.makedirs(INSTANCE_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL", f"sqlite:///{os.path.join(INSTANCE_DIR, 'firstapp.db')}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["UPLOAD_FOLDER"] = UPLOAD_DIR
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "False").lower() == "true"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["REMEMBER_COOKIE_HTTPONLY"] = True

csp = {
    "default-src": ["'self'"],
    "img-src": ["'self'", "data:", "https://cdn.jsdelivr.net"],
    "style-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
    "script-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
    "font-src": ["'self'", "https://cdn.jsdelivr.net"],
}

Talisman(
    app,
    force_https=os.getenv("FORCE_HTTPS", "False").lower() == "true",
    content_security_policy=csp,
    frame_options="DENY",
    strict_transport_security=False,
)

csrf = CSRFProtect(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["300 per day", "100 per hour"])


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class Student(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(100), nullable=False)
    lname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)


class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    subject = db.Column(db.String(120), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    submitted_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class Upload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False, unique=True)
    file_extension = db.Column(db.String(10), nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(150), nullable=False)
    ip_address = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


with app.app_context():
    db.create_all()

    admin_email = os.getenv("ADMIN_EMAIL")
    admin_password = os.getenv("ADMIN_PASSWORD")
    admin_username = os.getenv("ADMIN_USERNAME", "admin")

    if admin_email and admin_password:
        existing_admin = User.query.filter_by(email=admin_email.strip().lower()).first()
        if not existing_admin:
            db.session.add(
                User(
                    username=admin_username,
                    email=admin_email.strip().lower(),
                    password=bcrypt.generate_password_hash(admin_password).decode("utf-8"),
                    role="admin",
                    is_admin=True,
                )
            )
            db.session.commit()


@app.context_processor
def inject_session_data():
    return {
        "current_username": session.get("username"),
        "current_role": session.get("role"),
        "is_admin": session.get("is_admin", False),
    }


@app.after_request
def set_extra_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(413)
def request_entity_too_large(error):
    return render_template("413.html"), 413


@app.errorhandler(403)
def forbidden(error):
    return render_template("403.html"), 403


@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404


@app.errorhandler(429)
def ratelimit_handler(error):
    return render_template("429.html"), 429


@app.errorhandler(500)
def internal_server_error(error):
    db.session.rollback()
    return render_template("500.html"), 500


def log_action(action, user_id=None):
    db.session.add(
        AuditLog(
            user_id=user_id,
            action=action,
            ip_address=request.headers.get("X-Forwarded-For", request.remote_addr),
        )
    )
    db.session.commit()


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapped_view


def admin_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        if not session.get("is_admin"):
            abort(403)
        return view_func(*args, **kwargs)

    return wrapped_view


@app.route("/")
def root():
    if "user_id" in session:
        return redirect(url_for("home"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("3 per minute")
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip().lower()

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash("Username or email already exists.", "danger")
            return render_template("register.html", form=form)

        user = User(
            username=username,
            email=email,
            password=bcrypt.generate_password_hash(form.password.data).decode("utf-8"),
            role="user",
            is_admin=False,
        )
        db.session.add(user)
        db.session.commit()
        log_action("User registered", user.id)

        flash("Account created successfully. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("3 per minute")
def login():
    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, form.password.data):
            session.clear()
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = user.role
            session["is_admin"] = user.is_admin
            session.permanent = True
            log_action("User logged in", user.id)
            flash("Login successful.", "success")
            return redirect(url_for("home"))

        flash("Invalid email or password.", "danger")

    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    log_action("User logged out", session.get("user_id"))
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/home", methods=["GET", "POST"])
@login_required
def home():
    form = StudentForm()

    if form.validate_on_submit():
        student = Student(
            fname=form.fname.data.strip(),
            lname=form.lname.data.strip(),
            email=form.email.data.strip().lower(),
            city=form.city.data.strip(),
            age=form.age.data,
            created_by=session.get("user_id"),
        )
        db.session.add(student)
        db.session.commit()
        log_action("Student record created", session.get("user_id"))

        flash("Student record added successfully.", "success")
        return redirect(url_for("home"))

    all_students = Student.query.order_by(Student.sno.desc()).all()
    return render_template("index.html", form=form, all_students=all_students)


@app.route("/update/<int:sno>", methods=["GET", "POST"])
@login_required
def update(sno):
    student = Student.query.filter_by(sno=sno).first_or_404()
    form = StudentForm(obj=student)

    if form.validate_on_submit():
        student.fname = form.fname.data.strip()
        student.lname = form.lname.data.strip()
        student.email = form.email.data.strip().lower()
        student.city = form.city.data.strip()
        student.age = form.age.data
        db.session.commit()
        log_action(f"Student record updated: {sno}", session.get("user_id"))

        flash("Student record updated successfully.", "success")
        return redirect(url_for("home"))

    return render_template("update.html", form=form, student=student)


@app.route("/delete/<int:sno>", methods=["POST"])
@admin_required
def delete(sno):
    student = Student.query.filter_by(sno=sno).first_or_404()
    db.session.delete(student)
    db.session.commit()
    log_action(f"Student record deleted: {sno}", session.get("user_id"))

    flash("Student record deleted successfully. Only admins can do this.", "info")
    return redirect(url_for("home"))


@app.route("/contact", methods=["GET", "POST"])
@login_required
@limiter.limit("3 per minute")
def contact():
    form = ContactForm()

    if form.validate_on_submit():
        contact_record = Contact(
            full_name=form.full_name.data.strip(),
            email=form.email.data.strip().lower(),
            phone=form.phone.data.strip(),
            subject=form.subject.data.strip(),
            message=form.message.data.strip(),
            submitted_by=session.get("user_id"),
        )
        db.session.add(contact_record)
        db.session.commit()
        log_action("Contact form submitted", session.get("user_id"))

        flash("Contact details submitted successfully.", "success")
        return redirect(url_for("contact"))

    contacts = Contact.query.order_by(Contact.id.desc()).all()
    return render_template("contact.html", form=form, contacts=contacts)


@app.route("/upload", methods=["GET", "POST"])
@login_required
@limiter.limit("5 per minute")
def upload_file():
    form = FileUploadForm()

    if form.validate_on_submit():
        file = form.file.data

        if not file:
            flash("Please choose a file.", "danger")
            return redirect(url_for("upload_file"))

        if not allowed_file(file.filename):
            flash("Only PNG, JPG, JPEG, and PDF files are allowed.", "danger")
            return redirect(url_for("upload_file"))

        safe_name = secure_filename(file.filename)
        extension = safe_name.rsplit(".", 1)[1].lower()
        mime_type = file.mimetype or "application/octet-stream"

        if mime_type not in ALLOWED_MIME_TYPES:
            flash("Blocked file type. MIME type is not allowed.", "danger")
            return redirect(url_for("upload_file"))

        file.stream.seek(0, os.SEEK_END)
        size = file.stream.tell()
        file.stream.seek(0)

        if size > MAX_UPLOAD_SIZE:
            flash("File is too large. Maximum allowed size is 2 MB.", "danger")
            return redirect(url_for("upload_file"))

        unique_name = f"{uuid.uuid4().hex}.{extension}"
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], unique_name))

        upload = Upload(
            original_filename=safe_name,
            stored_filename=unique_name,
            file_extension=extension,
            mime_type=mime_type,
            size_bytes=size,
            uploaded_by=session.get("user_id"),
        )
        db.session.add(upload)
        db.session.commit()
        log_action(f"File uploaded: {safe_name}", session.get("user_id"))

        flash("File uploaded safely.", "success")
        return redirect(url_for("upload_file"))

    uploads = Upload.query.order_by(Upload.created_at.desc()).all()
    return render_template("upload.html", form=form, uploads=uploads)


@app.route("/uploads/<path:filename>")
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)


@app.route("/admin")
@admin_required
def admin_dashboard():
    stats = {
        "users": User.query.count(),
        "students": Student.query.count(),
        "contacts": Contact.query.count(),
        "uploads": Upload.query.count(),
    }
    users = User.query.order_by(User.created_at.desc()).all()
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(20).all()
    return render_template("admin.html", stats=stats, users=users, logs=logs)


@app.route("/admin/toggle_admin/<int:user_id>", methods=["POST"])
@admin_required
def toggle_admin(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == session.get("user_id"):
        flash("You cannot remove your own admin access from this screen.", "danger")
        return redirect(url_for("admin_dashboard"))

    user.is_admin = not user.is_admin
    user.role = "admin" if user.is_admin else "user"
    db.session.commit()
    log_action(f"Admin role toggled for user: {user.email}", session.get("user_id"))

    flash("User role updated successfully.", "success")
    return redirect(url_for("admin_dashboard"))

print("SECRET KEY:", app.config['SECRET_KEY'])

if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "False").lower() == "true")