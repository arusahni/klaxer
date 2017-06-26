"""Models for DTO and other ops."""
import datetime
from enum import Enum

TRANSFORMERS = {}

def transformer(name):
    """Decorator for transforms."""
    def decorator(func):
        """Register the transformer"""
        TRANSFORMERS[name] = func
        return func
    return decorator

class Alert:
    """An alert. Duh."""

    def __init__(self, service, *, title, message, timestamp, target, username, icon_emoji, icon_url):
        self.count = 0
        self.service = service
        self.message = message
        self.timestamp = timestamp
        self.severity = None
        self.target = target
        self.title = title
        self.username = username
        self.icon_emoji = icon_emoji
        self.icon_url = icon_url

    def __getitem__(self, item):
        return getattr(self, item)

    def __setitem__(self, item, value):
        return setattr(self, item, value)

    def __hash__(self):
        # Ignore timestamp since this is used to snooze
        return hash((self.severity, self.service, self.title, self.message))

    def to_dict(self):
        return {
            'count': self.count,
            'service': self.service,
            'message': self.message,
            'severity': str(self.severity),
            'target': self.target,
            'timestamp': self.timestamp,
            'title': self.title,
            'username': self.username,
            'icon_emoji': self.icon_emoji,
            'icon_url': self.icon_url
        }

    @classmethod
    def from_service(cls, service_name, data):
        """Get an instance of the class with normalized service data"""
        return cls(service_name, **TRANSFORMERS[service_name](data))


class NaiveContainer:
    """Holds any values you give to it and retrieves them safely."""
    def __init__(self, *args, **kwargs):
        if len(args) > 0:
            raise TypeError('NaiveContainer does not accept positional arguments')
        for kwarg in kwargs:
            setattr(self, kwarg, kwargs[kwarg])

    def __getattr__(self, name):
        return


class Message(NaiveContainer):
    """Naively holds attributes from a Slack message due to dynamic rendering."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __repr__(self):
        return '<%s.%s>' % (self.__class__.__name__, self.id)


@transformer('sensu')
def transform_sensu(data):
    """Decompose a sensu alert into arguments for an alert"""
    # TODO: maybe calulate a hashed alert ID here?
    return {
        'title': data['attachments'][0]['title'],
        'message': data['attachments'][0]['text'],
        'username': data['username'],
        'icon_emoji': data.get('icon_emoji'),
        'icon_url': data.get('icon_url'),
        'target': data['channel'].lstrip('#'),
        'timestamp': datetime.datetime.now(),
    }

class NoValueEnum(Enum):
    def __repr__(self):
        return '<%s.%s>' % (self.__class__.__name__, self.name)

class Severity(NoValueEnum):
    WARNING = 'warning'
    CRITICAL = 'critical'
    OK = 'ok'
    UNKNOWN = 'unknown'
