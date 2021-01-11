FROM python:3

WORKDIR /usr/src/app

COPY *.py ./
COPY requirements.txt ./

RUN pip install -r requirements.txt

ENTRYPOINT ["python"]