FROM ubuntu:20.04
# awaryjny
RUN DEBIAN_FRONTEND=noninteractive apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade
RUN DEBIAN_FRONTEND=noninteractive apt-get -yq install nginx python3-pip postgresql postgresql-contrib

RUN pip3 install --upgrade pip
RUN pip3 install uwsgi flask supervisor

EXPOSE 80
EXPOSE 443

ENTRYPOINT service nginx start && service postgresql start && /bin/bash