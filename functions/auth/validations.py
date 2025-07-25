def validateEmail(email: str) -> bool:
	import re

	email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

	return bool(re.match(email_regex, email))


def validatePassword(password: str) -> bool:
	# Define password validation criteria
	if len(password) < 8:
		return False
	if not any(char.isdigit() for char in password):
		return False
	if not any(char.isupper() for char in password):
		return False
	if not any(char.islower() for char in password):
		return False
	return bool(any(char in '!@#$%^&*()-_+=?' for char in password))
