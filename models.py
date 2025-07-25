from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Uuid
from sqlalchemy.orm import relationship
from database import Base


class User(Base):
	__tablename__ = 'users'

	id = Column(Uuid, primary_key=True, index=True)
	name = Column(String, index=True)
	email = Column(String, index=True)
	password = Column(String)
	created_on = Column(DateTime)

	# apikey = relationship('Apikey', back_populates='users')
	# fapshiapikey = relationship('FapshiApikey', back_populates='users')


class FapshiApikey(Base):
	__tablename__ = 'fapshi_api_keys'

	id = Column(Uuid, primary_key=True, index=True)
	key_value = Column(String, index=True)
	created_on = Column(DateTime)
	# owner = Column(Uuid, ForeignKey('users.id'))
	# user = relationship('User', back_populates='fapshi_api_keys')


class Apikey(Base):
	__tablename__ = 'api_keys'

	id = Column(Uuid, primary_key=True, index=True)
	key_value = Column(String, index=True)
	created_on = Column(DateTime)
	# owner = Column(Uuid, ForeignKey('users.id'))
	# user = relationship('User', back_populates='api_keys')
