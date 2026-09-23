# syntax=docker/dockerfile:1
# Auth service image: builds the console web UI, embeds it (-tags console remote),
# and produces a slim runtime carrying authsvc. Build context is the repo root so
# the module's replace directives (../.. , ../gateway, ../lcm) resolve.

FROM node:22-alpine AS ui
# The front-ends form one npm workspace (root package-lock.json) with the shared
# kit at ui/kit; install the workspace, build the kit, then the console (+ remote).
WORKDIR /w
COPY package.json package-lock.json .npmrc ./
COPY ui/kit/package.json ui/kit/
COPY services/gateway/shell/package.json services/gateway/shell/
COPY services/auth/console/package.json services/auth/console/
COPY services/asset/ui/package.json services/asset/ui/
COPY services/inventory/ui/package.json services/inventory/ui/
COPY services/ipam/ui/package.json services/ipam/ui/
COPY services/paperless/ui/package.json services/paperless/ui/
COPY services/deployer/ui/package.json services/deployer/ui/
COPY services/lcm/ui/package.json services/lcm/ui/
COPY services/notification/ui/package.json services/notification/ui/
COPY services/warden/ui/package.json services/warden/ui/
COPY services/ticket/ui/package.json services/ticket/ui/
COPY services/dns/ui/package.json services/dns/ui/
RUN npm ci --no-audit --no-fund
COPY ui/ ./ui/
RUN npm run -w ui/kit build
COPY services/auth/console/ ./services/auth/console/
RUN npm run -w services/auth/console build && npm run -w services/auth/console build:remote

FROM golang:1.26-alpine AS build
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY . .
COPY --from=ui /w/services/auth/console/dist ./services/auth/console/dist
COPY --from=ui /w/services/auth/console/dist-remote ./services/auth/console/dist-remote
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
