FROM python:3

WORKDIR /usr/src/app

COPY backend .
RUN pip install -r requirements.txt

CMD [ "python", "app.py" ]
