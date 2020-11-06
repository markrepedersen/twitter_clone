FROM node:13.12.0-alpine

WORKDIR /app

COPY frontend/package*.json ./
RUN npm install
COPY frontend .

CMD [ "npm", "start" ]
