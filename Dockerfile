FROM python:3.6
MAINTAINER Kevin Dwyer

COPY . /tmp/klaxer
RUN pip install -e "/tmp/klaxer/[dev]"

ENV PYTHONPATH=/klaxer

EXPOSE 8000

ENTRYPOINT ["bash"]
CMD ["-c", "hug -f /klaxer/klaxer.py"]
