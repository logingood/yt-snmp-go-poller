# syntax=docker/dockerfile:1
FROM golang:1.20
WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o poller cmd/poller/main.go

ENV GIN_MODE release
RUN cp /app/poller /bin/poller
CMD ["/bin/poller"]
