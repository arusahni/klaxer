"""The main Klaxer server"""

import logging

import hug
from falcon import HTTP_500

from klaxer.config import CLASSIFICATION_RULES, ENRICHMENTS, EXCLUSION_RULES, ROUTES
from klaxer.rules import Rules
from klaxer.errors import AuthorizationError, NoRouteFoundError, ServiceNotDefinedError
from klaxer.lib import classify, enrich, filtered, route, send, validate
from klaxer.models import Alert


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
            return {
                'status': 'ok',
                'count': alert.count,
                'service': alert.service,
                'message': alert.message,
                'severity': str(alert.severity),
                'target': alert.target
            }

        #The target channel gets queried for the most recent message. If it's identical, perform rollup. Otherwise, post the alert.
        send(alert)
        return {"status": "ok"}
    except (AuthorizationError, NoRouteFoundError, ServiceNotDefinedError) as error:
        logging.exception('Failed to serve an alert response')
        response.status = HTTP_500
        return {"status": error.message}
