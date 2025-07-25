from passlib.context import CryptContext

context = CryptContext(schemes=['bcrypt'], deprecated='auto')


def hash_password(value: str) -> str:
	"""Hashes a password using bcrypt."""
	return context.hash(value)


def verify_password(plain_value: str, hashed_value: str) -> bool:
	"""Verifies a plain text password against a hashed password."""
	return context.verify(plain_value, hashed_value)
