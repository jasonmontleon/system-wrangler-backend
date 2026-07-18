# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM quay.io/centos/centos:stream10 AS frontend-build
RUN dnf update -y \
 && dnf install -y --setopt=install_weak_deps=False nodejs npm \
 && dnf clean all && rm -rf /var/cache/dnf \
 && rm -f /usr/lib/sysimage/rpm/rpmdb.sqlite-shm /usr/lib/sysimage/rpm/rpmdb.sqlite-wal
WORKDIR /app
COPY --from=frontend package.json package-lock.json* ./
RUN npm ci
COPY --from=frontend . .
RUN npm run build

FROM --platform=$BUILDPLATFORM quay.io/centos/centos:stream10 AS backend-build
ARG GO_VERSION=1.26.5
ARG BACKEND_SHA=dev
ARG FRONTEND_SHA=dev
ARG BUILD_DATE=unknown
ARG TARGETARCH
RUN dnf update -y \
 && dnf install -y --setopt=install_weak_deps=False tar gzip curl-minimal \
 && dnf clean all && rm -rf /var/cache/dnf \
 && HOSTARCH=$(uname -m) \
 && case "$HOSTARCH" in \
        x86_64)  GOHOSTARCH=amd64 ;; \
        aarch64) GOHOSTARCH=arm64 ;; \
        s390x)   GOHOSTARCH=s390x ;; \
        ppc64le) GOHOSTARCH=ppc64le ;; \
        *) echo "unsupported build arch: $HOSTARCH" >&2; exit 1 ;; \
    esac \
 && curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GOHOSTARCH}.tar.gz" \
    | tar -C /usr/local -xz
ENV PATH=/usr/local/go/bin:$PATH
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
COPY --from=frontend-build /app/dist ./web/dist
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w \
        -X system-wrangler-backend/internal/buildinfo.Backend=${BACKEND_SHA} \
        -X system-wrangler-backend/internal/buildinfo.Frontend=${FRONTEND_SHA} \
        -X system-wrangler-backend/internal/buildinfo.BuildDate=${BUILD_DATE}" \
    -o /out/server \
    ./cmd/server

FROM quay.io/centos/centos:stream10
RUN dnf update -y \
 && dnf install -y --setopt=install_weak_deps=False \
        ca-certificates \
        catatonit \
        openssh-clients \
        ansible-core \
 && dnf clean all && rm -rf /var/cache/dnf \
 && rm -f /usr/lib/sysimage/rpm/rpmdb.sqlite-shm /usr/lib/sysimage/rpm/rpmdb.sqlite-wal \
 && ansible-galaxy collection install --collections-path /usr/share/ansible/collections ansible.windows \
 && useradd --uid 65532 --user-group --create-home --shell /sbin/nologin app
COPY --from=backend-build /out/server /usr/local/bin/server
RUN install -d -o app -g app -m 0750 /var/lib/system-wrangler \
 && install -d -o root -g app -m 0750 /etc/system-wrangler/tls
ENV DB_PATH=/var/lib/system-wrangler/system-wrangler.db
VOLUME ["/var/lib/system-wrangler"]
EXPOSE 8080 8443
USER app
ENTRYPOINT ["/usr/libexec/catatonit/catatonit", "--", "/usr/local/bin/server"]
