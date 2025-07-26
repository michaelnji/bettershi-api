import datetime
from typing import Any, Literal
import jwt
import os
from dotenv import load_dotenv

load_dotenv()

SIGNER_KEY = os.getenv('SIGNER_KEY')


def createJWT(date: datetime, user_id: str, role: Literal['authenticated']) -> str:
	encoded_data = jwt.encode(
		{
			'date': date.isoformat(),
			'user_id': user_id,
			'role': role,
			'issued_on': datetime.datetime.today().isoformat(),
		},
		SIGNER_KEY,
		algorithm='HS256',
	)
	return encoded_data


def decodeJWT(encodedJwt: str) -> Any:
	return jwt.decode(encodedJwt, SIGNER_KEY, algorithms='HS256')
