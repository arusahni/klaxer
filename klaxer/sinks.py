"""Data outflow"""

import re
import json
import logging
import urllib.request
from collections import namedtuple
from datetime import datetime

from slacker import Slacker

from klaxer import config, errors
from klaxer.models import Severity, Message

Channel = namedtuple('Channel', ['id', 'name'])
User = namedtuple('User', ['id', 'name', 'handle'])

# Regex pattern for text ending with dup indicators (e.g. "(x2)")
debounce_pattern = r'\(x(?P<count>\d+)\)$'
debounce_regex = re.compile(debounce_pattern)

# Regex pattern for Slack's URL markup: <http://url|url>
URL_PATTERN = re.compile(r'\<https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)\|(?P<url>.*?)\>')

class Destination:
    """Base for defining Slack destinations to send `Message`s to."""
    def __init__(self, token=config.SLACK_TOKEN):
        """Initalize the `Destination`.

        :param channel: the Slack channel name to send alerts to
        :param token: the Slack API token to use for requests

        """
        self.token = token
        self.host = 'https://slack.com/api/'
        self._alive = None

    def ping(self):
        """Check to see if the destination is reachable.

        :returns: whether or not the endpoint is available
        :rtype: bool

        """
        method = 'api.test'
        resource = f'{self.host}/{method}?token={self.token}'
        with urllib.request.urlopen(url) as response:
            response = json.loads(response.read())
        self.last_checked = datetime.utcnow()
        self._alive = response.get('ok', False)
        return self._alive

    @property
    def alive(self, window=config.WINDOW):
        """The status of the API based on the last ping.

        :returns: whether or not the API is available
        :rtype: bool

        """
        diff = datetime.utcnow() - self.last_checked
        if diff.total_seconds > window:
            self._alive = self.ping()
        return self._alive

    def send_alert(self):
        raise NotImplementedError('send_alert')


class Slack(Destination):
    """Use Slack as the destination."""
    def __init__(self, channel, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._channels = None
        self.slack = Slacker(self.token)
        self.channel = self.channels[channel]

    @property
    def channels(self):
        if not self._channels:
            self._channels = self.get_channels()
        return self._channels

    def ping(self):
        check = self.slack.auth.test()
        return check.successful

    def set_channel(self, channel_name):
        if channel_name not in self.channels:
            message = f'Channel {channel_name} is not an available channel'
            raise errors.ChannelNotFoundError(message)
        self.current_channel = self.channels.get(channel_name)

    def get_channels(self):
        channels = self.slack.channels.list(exclude_archived=True).body.get('channels')
        return {channel['name']: Channel(channel['id'], channel['name']) for channel in channels}

    def get_last_message(self):
        last_message = self.slack.channels.history(channel=self.channel.id, count=1).body.get('messages')[0]
        return Message(**last_message)

    def delete_message(self, message):
        response = self.slack.chat.delete(ts=message.ts, channel=self.channel.id)
        return response.successful

    def post_message(self, message):
        last_message = self.get_last_message()
        debounced = False
        if message in last_message.text:
            debounced = True
            message = debounce(last_message.text)
        response = self.slack.chat.post_message(channel=self.channel.id, text=message).body.get('message')
        if debounced:
            self.delete_message(last_message)
        return Message(**response)

    def send_alert(self, alert):
        last_message = self.get_last_message()
        debounced = False
        attachment = last_message.attachments[0] if last_message.attachments else None
        if attachment and alert.message in unslack_text(attachment['text']): #TODO: Test more than just the message
            debounced = True
            alert.message = debounce(attachment['text'])
        response = self.slack.chat.post_message(
            channel=self.channel.id,
            username=alert.username,
            icon_emoji=alert.icon_emoji,
            icon_url=alert.icon_url,
            attachments=[{
                'title': alert.title,
                'text': alert.message,
                'color': severity_to_color(alert.severity)
            }]).body.get('message')
        if debounced:
            self.delete_message(last_message)
        return Message(**response)

def severity_to_color(severity):
    """Map severity levels to colors"""
    # These colors are from the Tomorrow Night Eighties colorscheme:
    #  https://github.com/chriskempson/tomorrow-theme
    if severity == Severity.CRITICAL:
        return '#f2777a'
    elif severity == Severity.WARNING:
        return '#ffcc66'
    elif severity == Severity.OK:
        return '#99cc99'
    elif severity == Severity.UNKNOWN:
        return '#999999'
    raise ValueError('Invalid severity supplied')

def unslack_text(text):
    """Slack applies formatting to inline URLs. This undoes it"""
    has_url = URL_PATTERN.search(text)
    if has_url:
        # Searching only returns one match. Recursively unslack the message.
        return unslack_text(text.replace(has_url.group(0), has_url.group('url')))
    return text

def debounce(text):
    """Check for signs of a dup indicator, and increment the counter if present"""
    is_dup = debounce_regex.search(text)

    if is_dup:
        old_amount = is_dup.group('count')
        new_amount = str(int(old_amount) + 1)
        start, end = is_dup.span('count')
        return f'{text[:start]}{new_amount}{text[end:]}'
    return f'{text} (x2)'
