from argon2 import PasswordHasher
ph = PasswordHasher()

def hash_password(plain_password: str) -> str:
    return ph.hash(plain_password)

def verify_password(hashed_password: str, candidate: str) -> bool:
    try:
        return ph.verify(hashed_password, candidate)
    except Exception:
        return False
