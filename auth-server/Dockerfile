FROM golang:alpine AS build

WORKDIR /app

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY *.go .
RUN go build

FROM alpine as run

WORKDIR /app

COPY templates templates
COPY --from=build /app/auth-server /app/

RUN chmod +x auth-server
ENTRYPOINT [ "./auth-server" ]