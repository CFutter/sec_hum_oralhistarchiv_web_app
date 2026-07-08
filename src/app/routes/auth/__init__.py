"""Auth routes — login, registration, TOTP, and password reset."""

from fastapi import APIRouter
from .login import router as login_router
from .register import router as register_router
from .totp import router as totp_router
from .password_reset import router as password_reset_router
from .account import router as account_router
from .admin import router as admin_router
from .verify_email import router as email_verify_router
from .email_change import router as email_change_router


router = APIRouter()
router.include_router(login_router)
router.include_router(register_router)
router.include_router(totp_router)
router.include_router(password_reset_router)
router.include_router(account_router)
router.include_router(admin_router)
router.include_router(email_verify_router)
router.include_router(email_change_router)