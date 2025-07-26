from pydantic import BaseModel


class User(BaseModel):
	name: str
	email: str
	password: str
	# created_on: datetime

	class Config:
		orm_mode: True


class Apikey(BaseModel):
	key_value: str
	# created_on: datetime
	owner: str

	class Config:
		orm_mode: True


class FapshiApikey(BaseModel):
	key_value: str
	# created_on: datetime
	owner: str

	class Config:
		orm_mode: True
