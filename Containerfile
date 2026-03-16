FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates
ENV GOPROXY=direct
ENV GONOSUMDB=github.com/robert7528/hycore
ENV GONOSUMCHECK=github.com/robert7528/hycore
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -mod=mod -o hycert-api ./cmd/server

FROM alpine:3.20

RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/hycert-api .
COPY configs/ configs/
COPY deployment/entrypoint.sh entrypoint.sh
RUN chmod +x entrypoint.sh

RUN mkdir -p logs

EXPOSE 8082
ENTRYPOINT ["./entrypoint.sh"]
