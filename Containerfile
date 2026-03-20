FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates
ENV GOPROXY=direct
ENV GONOSUMDB=github.com/robert7528/hycore
ENV GONOSUMCHECK=github.com/robert7528/hycore
WORKDIR /app
COPY go.mod go.su[m] ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -mod=mod -o hycert ./cmd/hycert

FROM alpine:3.20

RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/hycert .
COPY configs/ configs/
COPY migrations/ migrations/
COPY deployment/entrypoint.sh .

RUN chmod +x entrypoint.sh && mkdir -p logs

EXPOSE 8082
ENTRYPOINT ["./entrypoint.sh"]
