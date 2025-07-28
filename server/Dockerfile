FROM node:20-alpine

WORKDIR /app/server

RUN apk add --no-cache curl openssl

RUN curl -LO https://github.com/smallstep/cli/releases/download/v0.26.2/step_linux_0.26.2_amd64.tar.gz \
    && tar -xzf step_linux_0.26.2_amd64.tar.gz \
    && mv step_0.26.2/bin/step /usr/local/bin/step \
    && chmod +x /usr/local/bin/step \
    && rm -rf step_0.26.2 step_linux_0.26.2_amd64.tar.gz

COPY package.json package-lock.json ./

RUN npm install -g npm@latest && npm ci --omit=dev

COPY . .

EXPOSE 8888

CMD ["npm", "start"]
