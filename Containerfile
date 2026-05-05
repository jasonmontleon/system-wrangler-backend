# syntax=docker/dockerfile:1.7

# Build the frontend SPA. The frontend lives in a separate repo and is
# supplied as a named build context:
#   podman build --build-context frontend=../cat-wrangler-frontend -t cat-wrangler:dev .
FROM docker.io/library/node:22-alpine AS frontend-build
WORKDIR /app
COPY --from=frontend package.json package-lock.json* ./
RUN npm ci
COPY --from=frontend . .
RUN npm run build

# Build the Go binary with the frontend embedded.
FROM docker.io/library/golang:1.24-alpine AS backend-build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
COPY --from=frontend-build /app/dist ./web/dist
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /out/server \
    ./cmd/server

# Final minimal image: distroless, non-root, no shell.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=backend-build /out/server /server
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/server"]
