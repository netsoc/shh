ARG NSJAIL_VERSION
FROM golang:1.17-alpine3.13 AS builder

WORKDIR /usr/local/lib/shhd
COPY go.* ./
RUN go mod download

COPY cmd/ ./cmd/
COPY pkg/ ./pkg/
RUN mkdir bin/ && CGO_ENABLED=0 go build -o bin/ ./cmd/...


FROM ghcr.io/devplayer0/nsjail-alpine:$NSJAIL_VERSION
ARG TARGETPLATFORM
ARG NETSOC_CLI_VERSION

RUN apk --no-cache add libc6-compat fish coreutils openssh-client curl nano vim man-db

RUN curl -fLo /usr/local/bin/netsoc "https://github.com/netsoc/cli/releases/download/v${NETSOC_CLI_VERSION}/cli-$(echo $TARGETPLATFORM | tr / - | tr -d v)" && \
    chmod +x /usr/local/bin/netsoc && \
    netsoc completion fish > /etc/fish/completions/netsoc.fish && \
    netsoc docs -t man -o /tmp/docs && \
    gzip /tmp/docs/man1/* && \
    mv /tmp/docs/man1 /usr/share/man/ && \
    rmdir /tmp/docs && \
    mandb

COPY --from=builder /usr/local/lib/shhd/bin/* /usr/local/bin/

EXPOSE 22/tcp
ENTRYPOINT ["/usr/local/bin/shhd"]

LABEL org.opencontainers.image.source https://github.com/netsoc/shh
