import os
import re
import secrets
import string
from datetime import date as date_cls
from pathlib import Path
import time

from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

from . import db
from .auth import role_required


BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "static" / "uploads" / "logos"
ALLOWED_EXTS = {".png", ".jpg", ".jpeg", ".gif"}


app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.environ.get("SECRET_KEY")


def generate_password(length: int = 6) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _slugify(value: str) -> str:
    value = (value or "").strip().lower()
    value = value.replace("ı", "i").replace("ğ", "g").replace("ü", "u").replace("ş", "s").replace("ö", "o").replace("ç", "c")
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = re.sub(r"-{2,}", "-", value).strip("-")
    return value or "sponsor"


def _unique_sponsor_id(base: str) -> str:
    candidate = base
    i = 2
    while db.get_sponsor_by_id(candidate):
        candidate = f"{base}-{i}"
        i += 1
    return candidate


def _validate_color(value: str) -> str:
    value = (value or "").strip()
    if re.fullmatch(r"#[0-9a-fA-F]{6}", value):
        return value
    return "#22d3ee"


def _save_logo(file_storage, sponsor_id: str) -> str | None:
    if not file_storage or not getattr(file_storage, "filename", ""):
        return None
    filename = secure_filename(file_storage.filename)
    _, ext = os.path.splitext(filename)
    ext = ext.lower()
    if ext not in ALLOWED_EXTS:
        return None
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    stored_name = f"{sponsor_id}{ext}"
    file_storage.save(str(UPLOAD_DIR / stored_name))
    return stored_name


@app.before_request
def _session_defaults():
    session.permanent = False


db.init_db()


# Simple in-memory rate limiting (per-process).
# Targets login endpoints to slow brute force attempts.
_RATE: dict[tuple[str, str], list[float]] = {}


def _client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _check_rate_limit(key: str, limit: int, window_seconds: int) -> None:
    now = time.time()
    ip = _client_ip()
    bucket_key = (ip, key)
    bucket = _RATE.get(bucket_key, [])
    cutoff = now - window_seconds
    bucket = [ts for ts in bucket if ts >= cutoff]
    if len(bucket) >= limit:
        abort(429)
    bucket.append(now)
    _RATE[bucket_key] = bucket


@app.before_request
def _rate_limit():
    # Don't rate limit static assets.
    if request.path.startswith("/static/"):
        return None
    if request.method != "POST":
        return None

    if request.path == "/login":
        _check_rate_limit("sponsor_login", limit=10, window_seconds=60)
    elif request.path == "/admin/login":
        _check_rate_limit("admin_login", limit=12, window_seconds=60)
    return None


@app.errorhandler(404)
def _not_found(_e):
    # Avoid breaking missing assets by redirecting them to HTML.
    if request.path.startswith("/static/"):
        return ("Not Found", 404)
    return redirect(url_for("index"))


@app.errorhandler(429)
def _too_many_requests(_e):
    # For sponsor login, bring user back to homepage with modal open.
    if request.path == "/login":
        return render_template(
            "index.html",
            modal_open=True,
            error="Too many attempts. Please wait a moment and try again.",
        ), 429
    return ("Too Many Requests", 429)


@app.get("/")
def index():
    return render_template("index.html", modal_open=False, error=None)


@app.post("/login")
def sponsor_login():
    plain_password = request.form.get("password", "")
    sponsor = db.verify_sponsor_password(plain_password)
    if not sponsor:
        return render_template("index.html", modal_open=True, error="Invalid password")

    session.clear()
    session["logged_in"] = True
    session["role"] = "sponsor"
    session["user_id"] = sponsor["id"]
    return redirect(url_for("sponsor_dashboard", sponsor_id=sponsor["id"]))


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.get("/sponsors/<sponsor_id>")
@role_required("sponsor")
def sponsor_dashboard(sponsor_id: str):
    if session.get("user_id") != sponsor_id:
        return redirect(url_for("sponsor_dashboard", sponsor_id=session.get("user_id")))

    sponsor = db.get_sponsor_by_id(sponsor_id)
    if not sponsor:
        session.clear()
        return redirect(url_for("index"))

    updates = db.get_all_updates()
    return render_template("dashboard.html", sponsor=sponsor, updates=updates)


@app.get("/admin/login")
def admin_login_page():
    return render_template("admin/login.html", error=None)


@app.post("/admin/login")
def admin_login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    expected_user = os.environ.get("ADMIN_USERNAME") or ""
    expected_pass = os.environ.get("ADMIN_PASSWORD") or ""

    if username != expected_user or password != expected_pass:
        return render_template("admin/login.html", error="Invalid credentials")

    session.clear()
    session["logged_in"] = True
    session["role"] = "admin"
    session["user_id"] = None
    return redirect(url_for("admin_panel"))


@app.get("/admin")
@role_required("admin")
def admin_panel():
    sponsors = db.get_all_sponsors()
    updates = db.get_all_updates()
    created_password = session.pop("_created_password", None)
    created_id = session.pop("_created_id", None)
    return render_template(
        "admin/panel.html",
        sponsor_count=len(sponsors),
        update_count=len(updates),
        created_password=created_password,
        created_id=created_id,
    )


@app.route("/admin/sponsors", methods=["GET", "POST"])
@role_required("admin")
def admin_sponsors():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        sponsor_type = (request.form.get("type") or "").strip() or None
        message = (request.form.get("message") or "").strip() or None
        color = _validate_color(request.form.get("color"))

        if not name:
            sponsors = db.get_all_sponsors()
            return render_template(
                "admin/sponsors.html", sponsors=sponsors, error="Name is required"
            )

        sponsor_id = _unique_sponsor_id(_slugify(name))
        plain_password = generate_password()

        logo_filename = _save_logo(request.files.get("logo"), sponsor_id)
        db.create_sponsor(
            sponsor_id=sponsor_id,
            name=name,
            plain_password=plain_password,
            color=color,
            logo=logo_filename,
            message=message,
            type=sponsor_type,
        )
        session["_created_password"] = plain_password
        session["_created_id"] = sponsor_id
        return redirect(url_for("admin_panel"))

    sponsors = db.get_all_sponsors()
    return render_template("admin/sponsors.html", sponsors=sponsors, error=None)


@app.route("/admin/sponsors/<sponsor_id>", methods=["GET", "POST"])
@role_required("admin")
def admin_edit_sponsor(sponsor_id: str):
    sponsor = db.get_sponsor_by_id(sponsor_id)
    if not sponsor:
        return redirect(url_for("admin_sponsors"))

    if request.method == "POST":
        name = (request.form.get("name") or "").strip() or sponsor["name"]
        sponsor_type = (request.form.get("type") or "").strip() or None
        message = (request.form.get("message") or "").strip() or None
        color = _validate_color(request.form.get("color") or sponsor["color"])

        logo_filename = _save_logo(request.files.get("logo"), sponsor_id)
        update_fields = {"name": name, "type": sponsor_type, "message": message, "color": color}
        if logo_filename:
            update_fields["logo"] = logo_filename
        db.update_sponsor(sponsor_id, **update_fields)
        return redirect(url_for("admin_edit_sponsor", sponsor_id=sponsor_id))

    sponsor = db.get_sponsor_by_id(sponsor_id)
    return render_template("admin/sponsor_edit.html", sponsor=sponsor, error=None)


@app.post("/admin/sponsors/<sponsor_id>/delete")
@role_required("admin")
def admin_delete_sponsor(sponsor_id: str):
    sponsor = db.get_sponsor_by_id(sponsor_id)
    if sponsor and sponsor["logo"]:
        try:
            (UPLOAD_DIR / sponsor["logo"]).unlink(missing_ok=True)
        except Exception:
            pass
    db.delete_sponsor(sponsor_id)
    return redirect(url_for("admin_sponsors"))


@app.route("/admin/updates", methods=["GET", "POST"])
@role_required("admin")
def admin_updates():
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        body = (request.form.get("body") or "").strip()
        d = (request.form.get("date") or "").strip() or date_cls.today().isoformat()
        if not title or not body:
            updates = db.get_all_updates()
            return render_template(
                "admin/updates.html",
                updates=updates,
                today=date_cls.today().isoformat(),
                error="Title and body are required",
            )
        db.create_update(title=title, body=body, date=d)
        return redirect(url_for("admin_updates"))

    updates = db.get_all_updates()
    return render_template(
        "admin/updates.html",
        updates=updates,
        today=date_cls.today().isoformat(),
        error=None,
    )


@app.post("/admin/updates/<int:update_id>/delete")
@role_required("admin")
def admin_delete_update(update_id: int):
    db.delete_update(update_id)
    return redirect(url_for("admin_updates"))

