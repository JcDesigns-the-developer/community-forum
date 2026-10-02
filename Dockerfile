FROM node:20-bookworm-slim
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
RUN mkdir -p /app/data
ENV NODE_ENV=production
ENV HOST=0.0.0.0
EXPOSE 3000
VOLUME ["/app/data"]
CMD ["npm","start"]
