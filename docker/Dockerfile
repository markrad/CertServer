FROM node:20.10.0-alpine3.19

RUN apk update
RUN apk add curl jq git
RUN npm install -g npm@10.2.5
RUN git -c advice.detachedHead=false clone -b v1.12.3 https://github.com/markrad/certserver.git
RUN mkdir /config
RUN printf "certServer:\n"  > /config/config.yml

WORKDIR /certserver

RUN npm install

# ADD healthcheck.sh ./healthcheck.sh
# HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 CMD [ "./healthcheck.sh" ]

CMD [ "node", "./output/src/index.js", "/config/config.yml" ]
