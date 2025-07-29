from typing import Any
from typing_extensions import Annotated
import uuid
from fastapi import FastAPI, Depends, Response, status, Header
from pydantic import BaseModel
from sqlalchemy.orm import Session
from whenever import Instant
from functions.auth.hashing import hash_password, verify_password
from functions.auth.signer import createJWT, decodeJWT, verifyJWTPayload
from functions.auth.validations import isTokenExpired, validateEmail, validatePassword
import models
import schemas
from database import engine, get_db


class responseModel(BaseModel):
	status: int
	message: str | None = None
	err: str | None = None
	data: Any | None = None


class loginModel(BaseModel):
	email: str
	password: str


class fapshiKey(BaseModel):
	key: str


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
		modified.created_on = Instant.now().format_common_iso()
		db_user = modified

		# Check if email already exists
		user_from_db = db.query(models.User).filter(models.User.email == db_user.email).first()
		if user_from_db and user_from_db.email == db_user.email:
			response.status_code = status.HTTP_409_CONFLICT
			return dict(
				status=400,
				err='User already exists.',
			)

		db.add(db_user)
		db.commit()
		db.refresh(db_user)

		# login new user & return access token (jwt)
		jwt_key = createJWT(Instant.now().format_common_iso(), str(modified.id), 'authenticated')
		data = models.Apikey()
		data.id = uuid.uuid4()
		data.created_on = Instant.now().format_common_iso()
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


@app.post('/auth/login', response_model=responseModel)
def login_user(user: loginModel, response: Response, db: Session = Depends(get_db)):
	try:
		# validate email & password
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

		# Check if user exists
		user_from_db = db.query(models.User).filter(models.User.email == user.email).first()
		if not user_from_db:
			response.status_code = status.HTTP_404_NOT_FOUND
			return dict(
				status=404,
				err='User not found.',
			)

		# validate password
		isValidPassword = verify_password(user.password, user_from_db.password)
		if not isValidPassword:
			response.status_code = status.HTTP_401_UNAUTHORIZED
			return dict(
				status=401,
				err='Invalid login credentials.',
			)

		# remove existing access token
		apikey_from_db = (
			db.query(models.Apikey).filter(models.Apikey.owner == user_from_db.id).first()
		)
		if apikey_from_db and apikey_from_db.key_value:
			db.delete(apikey_from_db)
			db.commit()
		# issue new access token
		jwt_key = createJWT(
			Instant.now().format_common_iso(), str(user_from_db.id), 'authenticated'
		)
		data = models.Apikey()
		data.id = uuid.uuid4()
		data.created_on = Instant.now().format_common_iso()
		data.key_value = jwt_key
		data.owner = str(user_from_db.id)
		apikey_details = data
		db.add(apikey_details)
		db.commit()
		db.refresh(apikey_details)

		# return new access token
		response.status_code = status.HTTP_200_OK
		return dict(status=200, message='Login successful', data={'access_token': jwt_key})
	except Exception as e:
		db.rollback()
		response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
		return dict(status=500, err=f'Error: {e}')


@app.post('/fapshi/add', response_model=responseModel)
def add_fapshi_key(
	body: fapshiKey,
	authorization: Annotated[str | None, Header()],
	response: Response,
	db: Session = Depends(get_db),
):
	access_token = authorization.split('Bearer ')[1]
	# check if access token exists
	if not access_token:
		response.status_code = status.HTTP_403_FORBIDDEN
		return dict(
			status=403,
			err='Invalid access token.',
		)
	# check if token is authentic and not tampered with
	payload = decodeJWT(access_token)
	isValidPayload = verifyJWTPayload(payload)
	if not isValidPayload:
		response.status_code = status.HTTP_403_FORBIDDEN
		return dict(
			status=403,
			err='Invalid access token.',
		)

	# check if oaykoad contains authentic user from our db
	user_id = payload['user_id']
	user_from_db = db.query(models.User).filter(models.User.id == user_id).first()

	if not user_from_db:
		response.status_code = status.HTTP_403_FORBIDDEN
		return dict(status=403, err='User not recognized.')

	# Check if access token has expired.
	if isTokenExpired(access_token):
		response.status_code = status.HTTP_403_FORBIDDEN
		return dict(status=403, err='Token has expired. Please login again.')

	# remove existing fapshi api key
	apikey_from_db = (
		db.query(models.FapshiApikey).filter(models.FapshiApikey.owner == user_from_db.id).first()
	)
	if apikey_from_db and apikey_from_db.key_value:
		db.delete(apikey_from_db)
		db.commit()

	data = models.FapshiApikey()
	data.id = uuid.uuid4()
	data.created_on = Instant.now().format_common_iso()
	data.key_value = body.key
	data.owner = str(user_from_db.id)
	apikey_details = data
	db.add(apikey_details)
	db.commit()
	db.refresh(apikey_details)
	response.status_code = status.HTTP_200_OK
	return dict(status=200, message='success', data=dict(user_id=user_id, fapshi_key=body.key))


@app.get('/fapshi/fetch', response_model=responseModel)
def get_fapshi_key(
	authorization: Annotated[str | None, Header()],
	response: Response,
	db: Session = Depends(get_db),
):
	access_token = authorization.split('Bearer ')[1]
	# check if access token exists
	if not access_token:
		response.status_code = status.HTTP_403_FORBIDDEN
		return dict(
			status=403,
			err='Invalid access token.',
		)
	# check if token is authentic and not tampered with
	payload = decodeJWT(access_token)
	isValidPayload = verifyJWTPayload(payload)
	if not isValidPayload:
		response.status_code = status.HTTP_403_FORBIDDEN
		return dict(
			status=403,
			err='Invalid access token.',
		)

	# check if oaykoad contains authentic user from our db
	user_id = payload['user_id']
	user_from_db = db.query(models.User).filter(models.User.id == user_id).first()

	if not user_from_db:
		response.status_code = status.HTTP_403_FORBIDDEN
		return dict(status=403, err='User not recognized.')

	# Check if access token has expired.
	if isTokenExpired(access_token):
		response.status_code = status.HTTP_403_FORBIDDEN
		return dict(status=403, err='Token has expired. Please login again.')

	# remove existing fapshi api key
	apikey_from_db = (
		db.query(models.FapshiApikey).filter(models.FapshiApikey.owner == user_from_db.id).first()
	)
	response.status_code = status.HTTP_200_OK
	return dict(status=200, message='success', data=dict(fapshi_key=apikey_from_db.key_value))


# for server health
@app.get('/status', response_model=responseModel)
def get_status() -> str:
	return dict(message='App is running well. All rights reserved (Bettershi-api)', status=200)
