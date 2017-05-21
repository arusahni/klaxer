FROM python:3.6
MAINTAINER Kevin Dwyer

COPY . /tmp/klaxer
RUN pip install -e "/tmp/klaxer/[dev]"

ENV PYTHONPATH=/klaxer
ENV FLASK_APP=klaxer.api
ENV FLASK_DEBUG=1

EXPOSE 8000

ENTRYPOINT ["bash"]
CMD ["-c", "flask run -p 8000"]
