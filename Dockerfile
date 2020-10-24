ARG NSJAIL_VERSION
FROM golang:1.15-alpine AS builder

WORKDIR /usr/local/lib/shhd
COPY go.* ./
RUN go mod download

COPY tools.go ./
RUN cat tools.go | sed -nr 's|^\t_ "(.+)"$|\1|p' | xargs -tI % go get %

COPY cmd/ ./cmd/
COPY pkg/ ./pkg/
RUN mkdir bin/ && CGO_ENABLED=0 go build -o bin/ ./cmd/...


FROM ghcr.io/devplayer0/nsjail-alpine:$NSJAIL_VERSION
RUN apk --no-cache add fish coreutils openssh-client curl

COPY --from=builder /usr/local/lib/shhd/bin/* /usr/local/bin/

EXPOSE 80/tcp
ENTRYPOINT ["/usr/local/bin/shhd"]
