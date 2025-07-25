from pydantic import BaseModel
from datetime import datetime


class User(BaseModel):
	name: str
	email: str
	password: str
	# created_on: datetime

	class Config:
		orm_mode: True


class Apikey(BaseModel):
	id: str
	key_value: str
	# created_on: datetime
	owner: str

	class Config:
		orm_mode: True


class FapshiApikey(BaseModel):
	id: str
	key_value: str
	# created_on: datetime
	owner: str

	class Config:
		orm_mode: True
