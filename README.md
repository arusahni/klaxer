# Klaxer - A webhook alert proxy

*Klaxon, Klax-off*

## Requirements

Python 3.6 only. Try to minimize deps on external daemons/processes.

## Docker Environment/Development

Build the docker image:
`docker build -t klaxer .`

Run the container:
`docker run -v $(pwd):/klaxer --name klaxer_instance -i -t klaxer`
This will start the hug server.

To get a shell in the container:
`docker exec -it klaxer_instance bash`

## Local Development

Install Klaxer and its development dependencies with:
`pip install -e .[dev]`

Run the klaxer server:
`hug -f klaxer/api.py`

Run the simulator:
`python -m klaxer.simulator`

## Registration

Klaxer uses a simple registration system to assign API keys to users for metrics and authorization.

### Getting a Key
After running an instance of the API, you can register for an API key by `POST`ing to the `/user/register` endpoint. 

```json
{
	"email": "foo@foo2.com",
	"name": "foo"
}
```

In return, you'll get an API key. **Careful!** At present, you'll only get to see this once. Klaxer staff can help recover it at present if you lose it.

**Response**
```json
{
    "id": 10,
    "api_key": "eab230d3d41b466db422ac4be3b7251c"
}
```

### Viewing Your Profile

After registering for a key, you can use this key to make requests. To see information in your profile like the amount of calls you've made. You need to make a **GET** request to the endpoint `/user/me`, setting the `x-api-key` header to your API key you received at registration.

```json
{
    "user_id": 10,
    "name": "Klaxer Fan",
    "email": "coolperson@klaxerboi.com",
    "registered": true,
    "approved": false,
    "signup_date": "2017-07-01",
    "api_key": "eab230d3d41b466db422ac4be3b7251c",
    "calls": 2,
    "messages": [
        "Welcome to Klaxer! Let staff know if you have any issues.",
        "Your account is currently unverified and may be limited until final approval."
    ]
}
```
