# syntax=docker/dockerfile:1.7

FROM quay.io/centos/centos:stream10 AS frontend-build
RUN dnf update -y \
 && dnf install -y --setopt=install_weak_deps=False nodejs npm \
 && dnf clean all && rm -rf /var/cache/dnf
WORKDIR /app
COPY --from=frontend package.json package-lock.json* ./
RUN npm ci
COPY --from=frontend . .
RUN npm run build

FROM quay.io/centos/centos:stream10 AS backend-build
ARG GO_VERSION=1.25.0
RUN dnf update -y \
 && dnf install -y --setopt=install_weak_deps=False tar gzip curl-minimal \
 && dnf clean all && rm -rf /var/cache/dnf \
 && ARCH=$(uname -m) \
 && case "$ARCH" in \
        x86_64)  GOARCH=amd64 ;; \
        aarch64) GOARCH=arm64 ;; \
        *) echo "unsupported arch: $ARCH" >&2; exit 1 ;; \
    esac \
 && curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" \
    | tar -C /usr/local -xz
ENV PATH=/usr/local/go/bin:$PATH
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
COPY --from=frontend-build /app/dist ./web/dist
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /out/server \
    ./cmd/server

FROM quay.io/centos/centos:stream10
RUN dnf update -y \
 && dnf install -y --setopt=install_weak_deps=False \
        ca-certificates \
        openssh-clients \
        ansible-core \
 && dnf clean all && rm -rf /var/cache/dnf \
 && useradd --uid 65532 --user-group --create-home --shell /sbin/nologin app
COPY --from=backend-build /out/server /usr/local/bin/server
RUN install -d -o app -g app -m 0750 /var/lib/system-wrangler \
 && install -d -o root -g app -m 0750 /etc/system-wrangler/tls
ENV DB_PATH=/var/lib/system-wrangler/system-wrangler.db
VOLUME ["/var/lib/system-wrangler"]
EXPOSE 8080 8443
USER app
ENTRYPOINT ["/usr/local/bin/server"]
