# syntax=docker/dockerfile:1
# Auth service image: builds the console web UI, embeds it (-tags console remote),
# and produces a slim runtime carrying authsvc. Build context is the repo root so
# the module's replace directives (../.. , ../gateway, ../lcm) resolve.

FROM node:22-alpine AS ui
WORKDIR /ui
COPY services/auth/console/package.json services/auth/console/package-lock.json* ./
RUN npm ci --no-audit --no-fund || npm install --no-audit --no-fund
COPY services/auth/console/ ./
RUN npm run build && npm run build:remote

FROM golang:1.26-alpine AS build
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY . .
COPY --from=ui /ui/dist ./services/auth/console/dist
COPY --from=ui /ui/dist-remote ./services/auth/console/dist-remote
WORKDIR /src/services/auth
ENV CGO_ENABLED=0 GOFLAGS=-buildvcs=false
RUN go build -tags "console remote" -o /out/authsvc ./cmd/authsvc

FROM alpine:3.20
RUN apk add --no-cache ca-certificates postgresql-client && adduser -D -u 10001 app
COPY --from=build /out/authsvc /usr/local/bin/
COPY services/auth/deploy /app/deploy
WORKDIR /app
USER app
ENTRYPOINT ["authsvc"]
CMD ["-config", "deploy/dev.yaml"]
