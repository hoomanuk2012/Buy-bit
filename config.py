# config.py
import os

class Settings:
    # --- عمومی
    SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_THIS_TO_A_LONG_RANDOM_STRING")
    PAYPAL_ENV = os.getenv("PAYPAL_ENV", "sandbox").lower()

    # --- HTTPS / کوکی‌ها
    FORCE_HTTPS = os.getenv("FORCE_HTTPS", "0") == "1"
    DEBUG = os.getenv("FLASK_DEBUG", "1") == "1"

    # در Dev باید False باشد تا کوکی سشن روی http کار کند
    SESSION_COOKIE_SECURE  = FORCE_HTTPS
    REMEMBER_COOKIE_SECURE = FORCE_HTTPS
    SESSION_COOKIE_SAMESITE  = "Lax"
    REMEMBER_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True

    # اگر از CSRF استفاده می‌کنی
    WTF_CSRF_ENABLED = True

    # PayPal CIDs از .env می‌آیند
    PAYPAL_CLIENT_ID_SANDBOX = os.getenv("PAYPAL_CLIENT_ID_SANDBOX", "")
    PAYPAL_CLIENT_ID_LIVE    = os.getenv("PAYPAL_CLIENT_ID_LIVE", "")

    @property
    def PAYPAL_CLIENT_ID(self):
        return (self.PAYPAL_CLIENT_ID_LIVE
                if self.PAYPAL_ENV == "live"
                else self.PAYPAL_CLIENT_ID_SANDBOX)

# یک نمونه singleton برای import در app.py
CFG = Settings()
