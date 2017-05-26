"""Errorz"""

class AuthorizationError(BaseException):
    message = "Could not authorize user"

class NoRouteFoundError(BaseException):
    message = "No alert route found"

class ChannelNotFoundError(BaseException):
    message = "Could not authorize user"

class ServiceNotDefinedError(BaseException):
    def __init__(self, message):
        self.message = f"No rules defined for service: {message}"

