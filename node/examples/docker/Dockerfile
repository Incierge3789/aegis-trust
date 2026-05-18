# @aegis_trust/sdk Docker quickstart — minimal demo image.
#
# Goal: docker compose up → curl :8080/demo/agent-request → see field
# filtering and audit log without installing anything on the host.
#
# Now that @aegis_trust/sdk is published on npm, the Dockerfile is a
# single-stage minimal install. No source-pack gymnastics needed.

FROM node:20-alpine AS build
WORKDIR /app
COPY package.json tsconfig.json ./
COPY agentServer.ts ./
RUN npm install --no-audit --no-fund \
 && npx tsc

FROM node:20-alpine
RUN addgroup -S aegis && adduser -S aegis -G aegis
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/package.json ./package.json
RUN mkdir -p /data && chown -R aegis /app /data

USER aegis
ENV PORT=8080
ENV AEGIS_AUDIT_PATH=/data/audit.jsonl

EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=2s --start-period=3s --retries=3 \
    CMD wget -q -O - http://localhost:8080/health || exit 1

CMD ["node", "dist/agentServer.js"]
