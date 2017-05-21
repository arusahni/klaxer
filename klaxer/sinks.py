import re
import urllib.request
from collections import namedtuple

from slacker import Slacker

from klaxer import config, errors

Channel = namedtuple('Channel', ['id', 'name'])
User = namedtuple('User', ['id', 'name', 'handle'])
Message = namedtuple('Message', ['ts', 'user', 'username', 'text', 'type', 'bot_id', 'bot_link', 'subtype'])
Message.__new__.__defaults__ = (None,) * len(Message._fields)


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
        logging.warning("Method send_alert not implemented!")
        return


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


def debounce(text):
    # Regex pattern for text ending with dup indicators (e.g. "(x2)")
    pattern = '\(x\d+\)$'
    reg = re.compile(pattern)

    # Check for signs of a dup indicator
    is_dup = reg.search(text)

    if is_dup:
        old_amount = is_dup.group(0).split('(x')[1].split(')')[0]
        new_amount = str(int(old_amount) + 1)
    else:
        return f'{text} (x2)'

    return text.replace(old_amount, new_amount)

