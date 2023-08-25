# FROM node:18.12.1-slim
FROM node:20.3.1-alpine3.18

# RUN apt update && apt -y upgrade
# RUN apt install -y git curl jq
RUN apk update
RUN apk add curl jq git
# RUN npm install -g npm@9.3.0
RUN npm install -g typescript
RUN git -c advice.detachedHead=false clone -b v1.2.7 https://github.com/markrad/certserver.git
RUN mkdir /config
RUN printf "certServer:\n"  > /config/config.yml

WORKDIR /certserver


# RUN npm install -g npm@9.4.2
RUN npm install
# RUN tsc

# ADD healthcheck.sh ./healthcheck.sh
# HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 CMD [ "./healthcheck.sh" ]

CMD [ "node", "./output/src/index.js", "/config/config.yml" ]
