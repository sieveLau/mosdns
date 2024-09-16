# syntax=docker/dockerfile:1

FROM golang:1.22 AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /mosdns

FROM alpine AS main

COPY --from=build /mosdns /
RUN mkdir -p /config
CMD ["/mosdns", "-d", "/config", "start", "-c", "config.yaml"]
