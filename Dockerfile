
FROM node:22.12.0-bookworm

WORKDIR /app

COPY get-refresh-token.js ./get-refresh-token.js
COPY index.js ./index.js
COPY words.json ./words.json

CMD ["node", "index.js"]
