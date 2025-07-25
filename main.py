from datetime import date
import datetime
from typing import Any
import uuid
from fastapi import FastAPI, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from functions.auth.hashing import hash_password
from functions.auth.validations import validateEmail, validatePassword
import models
import schemas
from database import engine, get_db


class responseModel(BaseModel):
	status: int
	message: str | None = None
	err: str | None = None
	data: Any | None = None


app = FastAPI()

models.Base.metadata.create_all(bind=engine)


@app.post('/auth/register', response_model=responseModel)
def register_user(user: schemas.User, db: Session = Depends(get_db)):
	try:
		if not validateEmail(user.email):
			return dict(
				status=400,
				err='Invalid email. Please make sure you are passing a valid email address',
			)

		if not validatePassword(user.password):
			return dict(
				status=400,
				err='Invalid password. Please make sure you are passing a valid password that is at least 8 characters long and contains at least one lowercase character, uppercase character, number and any symbol(!@#$%^&*()-_+=)',
			)

		modified = models.User(**user.dict())
		modified.password = hash_password(user.password)
		modified.id = uuid.uuid4()
		modified.created_on = datetime.datetime.now()
		db_user = modified
		db.add(db_user)
		db.commit()
		db.refresh(db_user)

		return dict(
			status=200,
			message='User successfully added',
			data=dict(email=db_user.email, name=db_user.name, created_on=db_user.created_on),
		)

	except Exception as e:
		db.rollback()

		# return error status
		return dict(status=500, err=f'Error: {e}')


# for server health
@app.get('/status')
def get_status() -> str:
	return 'App is running well. Exchange rates provided by Fapshi (https://fapshi.com)'
