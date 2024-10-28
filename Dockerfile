FROM python:3

RUN apt-get update && apt-get upgrade -y \
	&& apt-get install -y --no-install-recommends openssh-client sshpass \
	&& pip install pip --upgrade \
	&& pip install jinja2 packaging paramiko pyyaml

COPY configs/etc/ /configs/etc
COPY templates/ /templates
COPY kubify.py /
COPY helpers.py /

CMD ["kubify.py"]
