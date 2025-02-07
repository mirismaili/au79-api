ARG DOCKER_REGISTRY=docker.io
ARG NODE_VERSION
ARG BUN_VERSION

FROM node:${NODE_VERSION}-alpine AS node

FROM ${DOCKER_REGISTRY}/oven/bun:${BUN_VERSION}-alpine AS base

FROM base AS install-all-deps
# https://stackoverflow.com/questions/76109982/installing-specific-version-of-nodejs-and-npm-on-alpine-docker-image#answer-76132347
COPY --from=node /usr/lib /usr/lib
COPY --from=node /usr/local/lib /usr/local/lib
COPY --from=node /usr/local/include /usr/local/include
COPY --from=node /usr/local/bin /usr/local/bin

WORKDIR /app
COPY package.json package-lock.json ./
RUN time npm ci --ignore-scripts

FROM install-all-deps AS install-prod-deps
RUN time npm ci --ignore-scripts --omit=dev

FROM base AS builder-and-server-base
WORKDIR /app
ARG CI
ENV CI=$CI

FROM builder-and-server-base AS builder

COPY --from=install-all-deps /app/node_modules ./node_modules
COPY . ./

RUN time bun run build \
    && find . ! -name dist -mindepth 1 -maxdepth 1 -exec rm -rf {} + # Remove everything except "dist" folder

FROM builder-and-server-base AS server

RUN addgroup --system --gid 1001 bunjs
RUN adduser --system --uid 1001 elysia

COPY package.json ./
COPY --from=install-prod-deps /app/node_modules ./node_modules
COPY --from=builder --chown=elysia:bunjs /app/dist ./dist

USER elysia

EXPOSE 7979
CMD ["bun", "start"]
