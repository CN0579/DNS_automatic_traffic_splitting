FROM golang:1.25.12-alpine AS builder

WORKDIR /app

COPY . .
RUN go mod vendor
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -ldflags "-s -w" -o doh-autoproxy cmd/doh-autoproxy/main.go

FROM alpine:latest

WORKDIR /app

RUN apk --no-cache add ca-certificates

COPY --from=builder /app/doh-autoproxy .

EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 853/tcp
EXPOSE 853/udp
EXPOSE 443/tcp
EXPOSE 443/udp

CMD ["./doh-autoproxy"]
