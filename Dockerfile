# Build stage
FROM golang:1.23-alpine AS build
RUN apk add --no-cache git ca-certificates
WORKDIR /src

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/gochat ./cmd/gochat && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/loadtest ./cmd/loadtest

# Runtime stage
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/gochat /usr/local/bin/gochat
COPY --from=build /out/loadtest /usr/local/bin/loadtest
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/gochat"]
