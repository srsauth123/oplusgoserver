FROM golang:1.21-alpine AS builder
WORKDIR /build
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o server main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /build/server .
COPY config.yaml .
COPY admin ./admin
EXPOSE 8080
CMD ["./server", "config.yaml"]
