"""Core methods"""

from datetime import datetime

from klaxer.errors import AuthorizationError, NoRouteFoundError
from klaxer.models import Severity
from klaxer.sinks import Slack


def validate(service_name, token):
    #TODO: Implement. Raise AuthorizationError if invalid, otherwise just pass through
    pass

def classify(alert, rules):
    """Determine the severity of an alert

    :param alert: The alert to test
    :param rules: An array of classification rules to test against
    :returns: Alert - The Alert object with severity added
    """
    sev = []
    for rule in rules:
        sev.append(rule(alert))

    # Pick the highest priority classification from the classifications
    sev.sort(key=lambda x: x.value)
    alert.severity = sev.pop()

    return alert

def filtered(alert, rules):
    """Determine if an alert meets an exclusion rule

    :param alert: The alert to test
    :param rules: An array of exclusion rules to test against
    :returns: Boolean - True if the alert should be dropped
    """
    return any(rule(alert) for rule in rules)

def enrich(alert, rules):
    """Determine if an alert meets an enrichment rule

    :param alert: The alert to test
    :param rules: An array of enrichment rules to test against
    :returns: Alert - The enriched Alert object
    """
    for enrichment in rules:
        updates = enrichment(alert)
        if not updates:
            continue
        for name, value in updates.items():
            alert[name] = value

    return alert

def route(alert, rules):
    """Determine if an alert meets a routing rule

    :param alert: The alert to test
    :param rules: An array of routing rules to test against
    :returns: Alert - The routed Alert object
    """
    for route in rules:
        target = route(alert)
        if target:
            alert.target = target
            return alert
    raise NoRouteFoundError()

def send(alert):
    slack = Slack(alert.target)
    slack.send_alert(alert)
