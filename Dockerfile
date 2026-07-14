# Build stage — Alpine + static binary
FROM golang:1.25-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/krain-sec ./cmd/krain-sec \
 && mkdir -p /out/logs

# Runtime — tiny Alpine (static Go binary needs almost nothing)
FROM alpine:3.22

RUN adduser -D -H -u 65532 -g nonroot nonroot \
 && mkdir -p /app/logs \
 && chown -R nonroot:nonroot /app

WORKDIR /app

COPY --from=builder --chown=nonroot:nonroot /out/krain-sec /app/krain-sec
COPY --from=builder --chown=nonroot:nonroot /out/logs /app/logs
COPY --chown=nonroot:nonroot html /app/html

EXPOSE 8080 22 3306 3000

USER nonroot:nonroot

ENTRYPOINT ["/app/krain-sec"]
