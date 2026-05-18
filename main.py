import hashlib
import hmac
import os
import re
import secrets

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import models
from database import engine, get_db

models.Base.metadata.create_all(bind=engine)

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

DEFAULT_PRICE = float(os.getenv("VENTE_MAIL_PRICE", "1000"))
MIN_PAYOUT_BALANCE = float(os.getenv("MIN_PAYOUT_BALANCE", "4000"))
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
SESSION_SECRET = os.getenv("SESSION_SECRET", "change-this-secret-before-production")
SESSION_COOKIE = "vente_mail_session"
CSRF_COOKIE = "vente_mail_csrf"
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
VALID_STATUSES = {"En attente", "Payé", "Rejeté"}
PHONE_PATTERN = re.compile(r"^\+?\d{8,15}$")
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,80}$")


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000)
    return f"pbkdf2_sha256${salt}${digest.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    if password_hash.startswith("pbkdf2_sha256$"):
        _, salt, expected = password_hash.split("$", 2)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000)
        return hmac.compare_digest(digest.hex(), expected)
    return hmac.compare_digest(hashlib.sha256(password.encode("utf-8")).hexdigest(), password_hash)


def normalize_phone(phone: str) -> str:
    return re.sub(r"[\s.-]", "", phone.strip())


def sign_value(value: str) -> str:
    return hmac.new(SESSION_SECRET.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def make_session_value(user_id: int) -> str:
    value = str(user_id)
    return f"{value}.{sign_value(value)}"


def read_session_user_id(request: Request) -> int | None:
    raw_value = request.cookies.get(SESSION_COOKIE, "")
    if "." not in raw_value:
        return None
    value, signature = raw_value.rsplit(".", 1)
    if not value.isdigit() or not hmac.compare_digest(sign_value(value), signature):
        return None
    return int(value)


def set_session_cookie(response: RedirectResponse, user_id: int) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        make_session_value(user_id),
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=60 * 60 * 24 * 7,
    )


def get_csrf_token(request: Request) -> str:
    token = request.cookies.get(CSRF_COOKIE)
    if token and re.fullmatch(r"[a-f0-9]{64}", token):
        return token
    return secrets.token_hex(32)


def validate_csrf(request: Request, csrf_token: str) -> None:
    cookie_token = request.cookies.get(CSRF_COOKIE, "")
    if not cookie_token or not hmac.compare_digest(cookie_token, csrf_token):
        raise HTTPException(status_code=403, detail="Session expirée. Rechargez la page.")


def render(request: Request, template_name: str, context: dict | None = None, status_code: int = 200):
    context = context or {}
    csrf_token = get_csrf_token(request)
    context["csrf_token"] = csrf_token
    response = templates.TemplateResponse(request, template_name, context, status_code=status_code)
    response.set_cookie(
        CSRF_COOKIE,
        csrf_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=60 * 60 * 24,
    )
    return response


def get_current_user(request: Request, db: Session) -> models.User | None:
    user_id = read_session_user_id(request)
    if not user_id:
        return None
    return db.query(models.User).filter(models.User.id == user_id).first()


def require_client(request: Request, db: Session) -> models.User | RedirectResponse:
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/", status_code=303)
    return user


def require_admin(request: Request, db: Session) -> models.User | RedirectResponse:
    user = get_current_user(request, db)
    if not user or user.role != "admin":
        return RedirectResponse(url="/admin/login", status_code=303)
    return user


def bootstrap_admin(db: Session) -> None:
    admin = db.query(models.User).filter(models.User.username == ADMIN_USERNAME).first()
    if admin:
        if admin.role != "admin":
            admin.role = "admin"
            db.commit()
        return

    db.add(
        models.User(
            username=ADMIN_USERNAME,
            password=hash_password(ADMIN_PASSWORD),
            phone="0000000000",
            role="admin",
        )
    )
    db.commit()


def get_price(db: Session) -> float:
    setting = db.query(models.AppSetting).filter(models.AppSetting.key == "price").first()
    if not setting:
        setting = models.AppSetting(key="price", value=str(DEFAULT_PRICE))
        db.add(setting)
        db.commit()
        db.refresh(setting)
    return float(setting.value)


def get_user_balance(user_id: int, db: Session) -> float:
    paid_orders = (
        db.query(models.EmailOrder)
        .filter(models.EmailOrder.user_id == user_id, models.EmailOrder.status == "Payé")
        .all()
    )
    paid_payouts = (
        db.query(models.PayoutRequest)
        .filter(models.PayoutRequest.user_id == user_id, models.PayoutRequest.status == "Payé")
        .all()
    )
    return sum(order.price for order in paid_orders) - sum(payout.amount for payout in paid_payouts)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.on_event("startup")
def startup() -> None:
    db = next(get_db())
    try:
        bootstrap_admin(db)
        get_price(db)
    finally:
        db.close()


@app.get("/", response_class=HTMLResponse)
def login_page(request: Request):
    return render(request, "login.html", {"error": None, "min_payout_balance": MIN_PAYOUT_BALANCE})

@app.post("/register")
def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    phone: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf_token)
    username = username.strip()
    if not USERNAME_PATTERN.match(username):
        return render(
            request,
            "login.html",
            {
                "error": "Le nom doit contenir 3 à 80 caractères, sans espace.",
                "min_payout_balance": MIN_PAYOUT_BALANCE,
            },
            status_code=400,
        )
    if len(password) < 8:
        return render(
            request,
            "login.html",
            {
                "error": "Le mot de passe doit contenir au moins 8 caractères.",
                "min_payout_balance": MIN_PAYOUT_BALANCE,
            },
            status_code=400,
        )
    if password != confirm_password:
        return render(
            request,
            "login.html",
            {"error": "Les deux mots de passe ne sont pas identiques.", "min_payout_balance": MIN_PAYOUT_BALANCE},
            status_code=400,
        )
    phone = normalize_phone(phone)
    if not PHONE_PATTERN.match(phone):
        return render(
            request,
            "login.html",
            {
                "error": "Le numéro de téléphone doit être valable. Votre paiement sera envoyé sur ce numéro.",
                "min_payout_balance": MIN_PAYOUT_BALANCE,
            },
            status_code=400,
        )

    user_exists = db.query(models.User).filter(models.User.username == username).first()
    if user_exists:
        return render(
            request,
            "login.html",
            {"error": "Nom d'utilisateur déjà pris.", "min_payout_balance": MIN_PAYOUT_BALANCE},
            status_code=400,
        )

    new_user = models.User(username=username, password=hash_password(password), phone=phone)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    response = RedirectResponse(url="/dashboard", status_code=303)
    set_session_cookie(response, new_user.id)
    return response


@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf_token)
    user = db.query(models.User).filter(models.User.username == username.strip()).first()
    if not user or not verify_password(password, user.password):
        return render(
            request,
            "login.html",
            {"error": "Nom d'utilisateur ou mot de passe incorrect.", "min_payout_balance": MIN_PAYOUT_BALANCE},
            status_code=400,
        )

    response = RedirectResponse(
        url="/admin" if user.role == "admin" else "/dashboard",
        status_code=303,
    )
    set_session_cookie(response, user.id)
    return response


@app.post("/logout")
def logout(request: Request, csrf_token: str = Form(...)):
    validate_csrf(request, csrf_token)
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response

@app.post("/submit-email")
def submit_email(
    request: Request,
    email: str = Form(...),
    email_password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf_token)
    user = require_client(request, db)
    if isinstance(user, RedirectResponse):
        return user

    new_order = models.EmailOrder(
        email_submitted=email.strip(),
        email_password=email_password,
        price=get_price(db),
        status="En attente",
        user_id=user.id,
    )
    db.add(new_order)
    db.commit()
    return RedirectResponse(url="/dashboard", status_code=303)

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    user = require_client(request, db)
    if isinstance(user, RedirectResponse):
        return user

    orders = (
        db.query(models.EmailOrder)
        .filter(models.EmailOrder.user_id == user.id)
        .order_by(models.EmailOrder.created_at.desc())
        .all()
    )
    payout_requests = (
        db.query(models.PayoutRequest)
        .filter(models.PayoutRequest.user_id == user.id)
        .order_by(models.PayoutRequest.created_at.desc())
        .all()
    )
    balance = get_user_balance(user.id, db)
    has_pending_payout = any(payout.status == "En attente" for payout in payout_requests)
    return render(
        request,
        "dashboard.html",
        {
            "orders": orders,
            "user": user,
            "price": get_price(db),
            "balance": balance,
            "min_payout_balance": MIN_PAYOUT_BALANCE,
            "payout_requests": payout_requests,
            "can_request_payout": balance >= MIN_PAYOUT_BALANCE and not has_pending_payout,
            "has_pending_payout": has_pending_payout,
        },
    )


@app.post("/request-payout")
def request_payout(
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf_token)
    user = require_client(request, db)
    if isinstance(user, RedirectResponse):
        return user

    balance = get_user_balance(user.id, db)
    pending_request = (
        db.query(models.PayoutRequest)
        .filter(models.PayoutRequest.user_id == user.id, models.PayoutRequest.status == "En attente")
        .first()
    )
    if balance < MIN_PAYOUT_BALANCE or pending_request:
        return RedirectResponse(url="/dashboard", status_code=303)

    db.add(models.PayoutRequest(amount=balance, status="En attente", user_id=user.id))
    db.commit()
    return RedirectResponse(url="/dashboard", status_code=303)

# --- ROUTES ADMIN ---

@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_page(request: Request):
    return render(request, "login.html", {"error": None, "min_payout_balance": MIN_PAYOUT_BALANCE})


@app.get("/admin", response_class=HTMLResponse)
def admin_panel(request: Request, db: Session = Depends(get_db)):
    user = require_admin(request, db)
    if isinstance(user, RedirectResponse):
        return user

    orders = (
        db.query(models.EmailOrder)
        .order_by(models.EmailOrder.created_at.desc())
        .all()
    )
    payouts = (
        db.query(models.PayoutRequest)
        .order_by(models.PayoutRequest.created_at.desc())
        .all()
    )
    return render(
        request,
        "admin.html",
        {
            "orders": orders,
            "payouts": payouts,
            "price": get_price(db),
            "admin": user,
            "min_payout_balance": MIN_PAYOUT_BALANCE,
        },
    )

@app.post("/admin/update-status/{order_id}")
def update_status(
    order_id: int,
    request: Request,
    status: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf_token)
    user = require_admin(request, db)
    if isinstance(user, RedirectResponse):
        return user
    if status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail="Statut invalide")

    order = db.query(models.EmailOrder).filter(models.EmailOrder.id == order_id).first()
    if order:
        order.status = status
        db.commit()
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/price")
def update_price(
    request: Request,
    price: float = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf_token)
    user = require_admin(request, db)
    if isinstance(user, RedirectResponse):
        return user
    if price <= 0:
        raise HTTPException(status_code=400, detail="Le prix doit être supérieur à 0")

    setting = db.query(models.AppSetting).filter(models.AppSetting.key == "price").first()
    if not setting:
        setting = models.AppSetting(key="price", value=str(price))
        db.add(setting)
    else:
        setting.value = str(price)
    db.commit()
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/update-payout/{payout_id}")
def update_payout(
    payout_id: int,
    request: Request,
    status: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf_token)
    user = require_admin(request, db)
    if isinstance(user, RedirectResponse):
        return user
    if status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail="Statut invalide")

    payout = db.query(models.PayoutRequest).filter(models.PayoutRequest.id == payout_id).first()
    if payout:
        payout.status = status
        db.commit()
    return RedirectResponse(url="/admin", status_code=303)
