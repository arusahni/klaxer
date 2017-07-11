"""The main Klaxer server"""

import logging
import json

import hug
from falcon import HTTP_400, HTTP_500

from klaxer.rules import Rules
from klaxer.errors import AuthorizationError, NoRouteFoundError, ServiceNotDefinedError
from klaxer.lib import classify, enrich, filtered, route, send, validate
from klaxer.models import Alert
from klaxer.users import create_user, add_message, bootstrap, api_key_authentication, is_existing_user


CURRENT_FILTERS = []

RULES = Rules()

@hug.post('/alert/{service_name}/{token}')
def incoming(service_name: hug.types.text, token: hug.types.text, response, debug=False, body=None):
    """An incoming alert. The core API method"""
    try:
        validate(service_name, token)
        alert = Alert.from_service(service_name, body)
        alert = classify(alert, RULES.get_classification_rules(service_name))
        # Filter based on rules (e.g. junk an alert if a string is in the body or if it came from a CI bot).
        if filtered(alert, RULES.get_exclusion_rules(service_name)):
            return
        #Filtered based on user interactions (e.g. bail if we've snoozed the notification type snoozed).
        if filtered(alert, CURRENT_FILTERS):
            return
        #Enriched based on custom rules (e.g. all alerts with 'keepalive' have '@deborah' appended to them so Deborah gets an extra level of notification priority.
        alert = enrich(alert, RULES.get_enrichment_rules(service_name))
        # Determine where the message goes
        alert = route(alert, RULES.get_routing_rules(service_name))

        # Present relevant debug info without actually sending the Alert
        if debug:
            return alert.to_dict()

        #The target channel gets queried for the most recent message. If it's identical, perform rollup. Otherwise, post the alert.
        send(alert)
        return {"status": "ok"}
    except (AuthorizationError, NoRouteFoundError, ServiceNotDefinedError) as error:
        logging.exception('Failed to serve an alert response')
        response.status = HTTP_500
        return {"status": error.message}


@hug.post('/user/register')
def register(response, body=None):
    """Register for Klaxer and get a key in return."""
    if not body:
        response.status = HTTP_400
        return {"status": "No request body provided"}
    email = body.get('email')
    name = body.get('name')
    if not email or not name:
        response.status = HTTP_400
        return {"status": "Please provide a valid name and email."}
    if is_existing_user(email):
        response.status = HTTP_400
        return {"status": f"Email {email} is already registered"}
    user = create_user(name=name, email=email)
    return {
        'id': user.id,
        'api_key': user.api_key
    }


@hug.get('/user/me', requires=api_key_authentication)
def profile(user: hug.directives.user, response, body=None):
    """If authenticated, give the user back their profile information."""
    return user.to_dict()


@hug.startup()
def startup(api):
    """Bootstrap the database when the API starts."""
    bootstrap()