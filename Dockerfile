FROM golang:1.19.3-buster as builder

WORKDIR /auth

COPY go.* ./
RUN go mod download
COPY . ./

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -v -ldflags "-X main.version=0.0.1 -X main.build=`date -u +.%Y%m%d.%H%M%S`" \
    -o run cmd/auth/main.go

FROM alpine:latest

WORKDIR /auth

COPY --from=builder /auth/run /auth/run
COPY --from=builder /auth/.env /auth/.env
COPY --from=builder /auth/public /auth/public/

EXPOSE 80 4000Be

RUN mkdir -p /auth/logs && \
    apk update && apk add curl && apk add --no-cache bash && \
    apk add dumb-init
ENTRYPOINT ["/usr/bin/dumb-init", "--"]

CMD ./run