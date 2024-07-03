FROM debian:12.6
RUN apt update && apt install -y pypy3 && mkdir -p /app && mkdir -p /scan
ADD datarake.py /app/datarake.py

CMD ["/usr/bin/pypy3", "/app/datarake.py", "/scan"]
