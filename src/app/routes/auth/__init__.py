"""Authentication route collection."""

from .account import routers as account_routers
from .admin import routers as admin_routers
from .admin_promotion import routers as admin_promotion_routers
from .email_change import routers as email_change_routers
from .login import routers as login_routers
from .password_reset import routers as password_reset_routers
from .register import routers as register_routers
from .totp import routers as totp_routers
from .totp_recover import routers as totp_recovery_routers
from .verify_email import routers as email_verify_routers

routers = (
    *login_routers,
    *totp_recovery_routers,
    *register_routers,
    *totp_routers,
    *password_reset_routers,
    *account_routers,
    *admin_promotion_routers,
    *admin_routers,
    *email_verify_routers,
    *email_change_routers,
)

__all__ = ["routers"]
