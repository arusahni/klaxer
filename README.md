# Klaxer - A webhook alert proxy

*Klaxon, Klax-off*

## Requirements

Python 3.6 only. Try to minimize deps on external daemons/processes.

Install dependencies with:
`pip install -e .[dev]`

## Docker Environment

Build the docker image:
`docker build -t klaxer .`

Run the container:
`docker run -v $(pwd):/klaxer --name klaxer_instance -i -t klaxer`
This will start the hug server.

To get a shell in the container:
`docker exec -it klaxer_instance bash`

## Development
Run the klaxer server:
`hug -f klaxer/api.py`

Run the simulator:
`python -m klaxer.simulator`
