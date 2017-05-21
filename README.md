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

Run the klaxer server:
`flask run -p 8000 &`

Run the simulator:
`python -m klaxer.simulator`
