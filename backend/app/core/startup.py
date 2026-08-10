"""
Startup validation and health checks for EFF-Monitoring v2.1.4.

Performs security configuration checks and database connectivity
validation at application startup. In production-like environments
(PostgreSQL), insecure defaults trigger prominent warnings.
"""

import logging

from sqlalchemy import text

from app.core.settings import get_settings

logger = logging.getLogger("eff.startup")

INSECURE_JWT_SECRETS = {"change-me-in-production", "", "secret", "dev-secret"}
INSECURE_ADMIN_PASSWORDS = {"admin123", "admin", "password", "123456"}


def validate_security_config(settings=None) -> list[str]:
    """Check security-critical settings. Returns a list of warning messages."""
    if settings is None:
        settings = get_settings()
    warnings: list[str] = []

    if settings.jwt_secret in INSECURE_JWT_SECRETS:
        warnings.append(
            f"JWT_SECRET is set to an insecure default value ({settings.jwt_secret!r}). "
            f"Generate a strong secret: "
            f"python -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )

    if settings.initial_admin_password in INSECURE_ADMIN_PASSWORDS:
        warnings.append(
            f"INITIAL_ADMIN_PASSWORD is set to an insecure default value "
            f"({settings.initial_admin_password!r}). "
            f"Change it in your .env file or INITIAL_ADMIN_PASSWORD environment variable."
        )

    return warnings


def check_database_connectivity(db_session_maker) -> bool:
    """Verify the database is reachable. Returns True if healthy."""
    try:
        db = db_session_maker()
        db.execute(text("SELECT 1"))
        db.close()
        return True
    except Exception as exc:
        logger.error("Database connectivity check failed: %s", exc)
        return False


def run_startup_checks(settings=None, db_session_maker=None) -> None:
    """Run all startup validation checks.

    Called once during FastAPI startup event. Logs security warnings
    and database status.
    """
    if settings is None:
        settings = get_settings()

    warnings = validate_security_config(settings)
    for w in warnings:
        logger.warning("=== SECURITY WARNING === %s", w)

    if db_session_maker:
        if check_database_connectivity(db_session_maker):
            logger.info("Database connectivity check: OK")
        else:
            logger.error("Database connectivity check: FAILED")

    if warnings and settings.is_production_like:
        logger.warning(
            "=== Running with insecure defaults in a production-like environment! ===\n"
            "=== Set JWT_SECRET and INITIAL_ADMIN_PASSWORD in .env before deploying. ==="
        )
