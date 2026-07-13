# Build stage
FROM golang:1.25-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/krain-sec ./cmd/krain-sec

# Runtime stage
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

COPY --from=builder /out/krain-sec /app/krain-sec
COPY html /app/html

EXPOSE 8080 2222

USER nonroot:nonroot

ENTRYPOINT ["/app/krain-sec"]
