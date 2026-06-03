FROM cgr.dev/chainguard/python:latest-dev

USER root
RUN python3 -m pip install pipenv

RUN mkdir -p /app/datarake /src
COPY Pipfile /app
COPY Pipfile.lock /app
COPY drrun.sh /app
COPY ./datarake /app/datarake

WORKDIR /app
RUN pipenv install --system

#USER nobody
ENV PYTHONPATH=/app

ENTRYPOINT [ "/app/drrun.sh" ]
