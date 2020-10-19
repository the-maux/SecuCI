FROM python:3.8

WORKDIR /home/app
RUN git clone https://github.com/lyvd/bandit4mal.git
WORKDIR /home/app/bandit4mal
COPY banditController.py .

RUN python setup.py install

RUN pip3 -q install -r requirements.txt  requests PyGithub

COPY banditController.py .
RUN python banditController.py --configure

RUN pip install -q -r requirements-pentest.txt

ENTRYPOINT python banditController.py --start
