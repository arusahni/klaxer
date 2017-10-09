"""Methods, classes, and functions for getting your Klaxer registration on."""

import json
import logging
from uuid import uuid4
from datetime import datetime

import hug
from sqlalchemy import create_engine, ForeignKey, Column, Integer, String, \
    Boolean, Date, Text
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base

from klaxer import config


engine = create_engine(config.DB_CONNECTION_STRING)
Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()


class KlaxerUser(Base):
    """The default object for users requiring a registration in Klaxer."""
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String)
    email = Column(String)
    registered = Column(Boolean, default=False)
    approved = Column(Boolean, default=False)
    signup_date = Column(Date, default=datetime.utcnow())
    api_key = Column(String, default=None)
    calls = Column(Integer, default=0)
    messages = relationship("KlaxerMessage", backref="user")

    def __repr__(self):
        return '<KlaxerUser {}>'.format(self.id)

    def to_dict(self):
        """Dump the user object to a `dict`.

        :returns: the user object as a `dict`
        :rtype: `dict`

        """
        return {
            'user_id': self.id,
            'name': self.name,
            'email': self.email,
            'registered': self.registered,
            'approved': self.approved,
            'signup_date': self.signup_date,
            'api_key': self.api_key,
            'calls': self.calls,
            'messages': [message.text for message in self.messages]
        }

    def to_json(self, *args, **kwargs):
        """Dump the user object to JSON.

        Accepts arguments and keyword arguments for `json.dumps()`.
        """
        body = self.to_dict()
        body['signup_date'] = body['signup_date'].isoformat()
        return json.dumps(body, *args, **kwargs)


class KlaxerMessage(Base):
    """Message to display to users."""
    __tablename__ = 'message'

    id = Column(Integer, primary_key=True)
    text = Column(Text)
    user_id = Column(Integer, ForeignKey('user.id'))
    can_dismiss = Column(Boolean, default=True)

    def __repr__(self):
        return '<KlaxerMessage {}>'.format(self.id)


def register(name, email):
    """Register for an API key with the given name and email.

    :param name: the name of the user/organization
    :param email: the contact email for the user
    :returns: an instance the of the user object that was registered
    :rtype: `klaxer.users.KlaxerUser`

    """
    user = KlaxerUser(name=name, email=email)
    user.api_key = uuid4().hex
    user.registered = True
    session.add(user)
    session.commit()
    return user


def create_user(name, email):
    """Create a user via registration, and add the welcome messages.

    :param name: the name of the user/organization
    :param email: the contact email for the user
    :returns: an instance of the user object that was registered
    :rtype: `klaxer.users.KlaxerUser`

    """
    user = register(name, email)
    add_message(user=user, text=config.MSG_WELCOME)
    add_message(user=user, text=config.MSG_UNVERIFIED, can_dismiss=False)
    return user


def approve(user):
    """Approve a registered user so that they can use API endpoints.

    :param user: an instance of the `KlaxerUser` object to verify
    :returns: an instance of the user that matched after updating it
    :rtype: `klaxer.users.KlaxerUser`

    """
    if user.approved:
        logging.warn('noop - User %d already approved', user.id)
        return user
    user.approved = True
    for message in user.messages:
        if message.text == config.MSG_WELCOME:
            session.delete(message)
    session.add(user)
    session.commit()
    return user


def add_message(user, text, can_dismiss=True):
    """Add a message to the user's message queue for a variety of purposes.

    :param user: the instance of `KlaxerUser` to add a message to
    :param text: the text of the message
    :param can_dismiss: (optional) whether or not the message can be dismissed
    :returns: an instance of the `KlaxerMessage` that was created
    :rtype: `klaxer.users.KlaxerMessage`

    """
    message = KlaxerMessage(text=text, user=user, can_dismiss=can_dismiss)
    session.add(message)
    session.commit()
    return message


def is_existing_user(email):
    """Determine whether or not the given email is registered.

    :param email: the email to use for registration
    :returns: whether or not the user is already registered
    :rtype: `bool`

    """
    if not email:
        return False
    user = session.query(KlaxerUser).filter(KlaxerUser.email==email).first()
    return True if user else False


def bootstrap():
    """Bootstrap the Klaxer user database."""
    Base.metadata.create_all(engine)


def verify(api_key):
    """Verify that the API key provided is valid."""
    user = session.query(KlaxerUser).filter(KlaxerUser.api_key==api_key).first()
    if user:
        user.calls += 1
    session.add(user)
    session.commit()
    return user


# This is used as a middleware for hug to do verification
api_key_authentication = hug.authentication.api_key(verify)
