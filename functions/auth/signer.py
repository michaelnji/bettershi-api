import datetime
from typing import Any, Literal
import jwt
import os
from dotenv import load_dotenv
from whenever import Instant

load_dotenv()

SIGNER_KEY = os.getenv('SIGNER_KEY')


def createJWT(date: datetime, user_id: str, role: Literal['authenticated']) -> str:
	encoded_data = jwt.encode(
		{
			'date': date,
			'user_id': user_id,
			'role': role,
			'issued_on': Instant.now().format_common_iso(),
			'expires': Instant.now().add(minutes=50).format_common_iso(),
		},
		SIGNER_KEY,
		algorithm='HS256',
	)
	return encoded_data


def decodeJWT(encodedJwt: str) -> Any:
	try:
		return jwt.decode(encodedJwt, SIGNER_KEY, algorithms='HS256')
	except jwt.DecodeError:
		# Handle the error appropriately, e.g., log it or raise a custom exception
		return False


def verifyJWTPayload(data: Any):
	if not data:
		return False
	return (
		data['user_id']
		and data['role']
		and data['role'] == 'authenticated'
		and data['issued_on']
		and data['expires']
	)
