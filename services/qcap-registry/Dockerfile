# syntax=docker/dockerfile:1

FROM golang:1.27.1-alpine3.24 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/qcap-registry .

FROM alpine:3.24
RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 10001 qcap \
    && adduser -S -D -H -u 10001 -G qcap qcap \
    && mkdir -p /var/lib/qcap \
    && chown -R qcap:qcap /var/lib/qcap

COPY --from=build /out/qcap-registry /usr/local/bin/qcap-registry

ENV QCAP_REGISTRY_ADDR=:8080 \
    QCAP_REGISTRY_STORE=/var/lib/qcap \
    QCAP_REGISTRY_INDEX=/var/lib/qcap/index.json

USER 10001:10001
EXPOSE 8080
VOLUME ["/var/lib/qcap"]

HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD wget -q -O /dev/null http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["/usr/local/bin/qcap-registry"]
