def validateEmail(email: str) -> bool:
	import re

	# Define a regular expression pattern for validating an Email
	email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

	# Use the re.match function to check if the email matches the pattern
	if re.match(email_regex, email):
		return True
	else:
		return False


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
	if not any(char in '!@#$%^&*()-_+=?' for char in password):
		return False
	return True
