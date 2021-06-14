FROM python:3-slim

RUN apt-get update && apt-get upgrade -y \
	&& apt-get install -y --no-install-recommends openssh-client sshpass \
	&& pip install pip --upgrade \
	&& pip install packaging jinja2 pyyaml

COPY configs/etc/ /configs/etc
COPY templates/ /templates
COPY kubify.py /
COPY helpers.py /

CMD ["kubify.py"]
