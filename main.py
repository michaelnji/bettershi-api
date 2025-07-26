import datetime
from typing import Any
import uuid
from fastapi import FastAPI, Depends, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from functions.auth.hashing import hash_password
from functions.auth.signer import createJWT
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
def register_user(user: schemas.User, response: Response, db: Session = Depends(get_db)):
	try:
		if not validateEmail(user.email):
			response.status_code = status.HTTP_400_BAD_REQUEST
			return dict(
				status=400,
				err='Invalid email. Please make sure you are passing a valid email address',
			)

		if not validatePassword(user.password):
			response.status_code = status.HTTP_400_BAD_REQUEST
			return dict(
				status=400,
				err='Invalid password. Please make sure you are passing a valid password.',
			)

		modified = models.User(**user.dict())
		modified.password = hash_password(user.password)
		modified.id = uuid.uuid4()
		modified.created_on = datetime.datetime.now()
		db_user = modified
		db.add(db_user)
		db.commit()
		db.refresh(db_user)

		jwt_key = createJWT(datetime.datetime.now(), str(modified.id), 'authenticated')
		data = models.Apikey()
		data.id = uuid.uuid4()
		data.created_on = datetime.datetime.now()
		data.key_value = jwt_key
		data.owner = str(modified.id)
		apikey_details = data
		db.add(apikey_details)
		db.commit()
		db.refresh(apikey_details)

		response.status_code = status.HTTP_201_CREATED
		return dict(
			status=201,
			message='User successfully added',
			data=dict(
				email=db_user.email,
				name=db_user.name,
				created_on=db_user.created_on,
				access_token=str(jwt_key),
			),
		)

	except Exception as e:
		db.rollback()
		response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
		# return error status
		return dict(status=500, err=f'Error: {e}')


# for server health
@app.get('/status', response_model=responseModel)
def get_status() -> str:
	return dict(message='App is running well. All rights reserved (Bettershi-api)', status=200)
