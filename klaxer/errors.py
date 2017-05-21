"""Errorz"""

class AuthorizationError(BaseException):
    message = "Could not authorize user"

class NoRouteFoundError(BaseException):
    message = "No alert route found"

class ChannelNotFoundError(BaseException):
    message = "Could not authorize user"
