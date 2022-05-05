FROM golang:bullseye as build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION
ARG BUILD_DATE
ARG YARA_VERSION=4.2.1

WORKDIR /src

# Build yara dependency
RUN apt update && apt install -y wget automake libtool make gcc pkg-config libssl-dev libmagic-dev

ADD https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz /src

RUN tar xvfz /src/v${YARA_VERSION}.tar.gz && cd yara-${YARA_VERSION} && \
    ./bootstrap.sh && \
    ./configure --enable-magic && \
    make && \
    make install

# Build golang rest api
COPY . /src

RUN env GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=1 go mod download && \
  export GIT_COMMIT=$(git rev-parse HEAD) && \
  export GIT_DIRTY="" && \
  env GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=1 \
    go build -o yara-rest-api \
    -ldflags "-X github.com/sqooba/go-common/version.GitCommit=${GIT_COMMIT}${GIT_DIRTY} \
              -X github.com/sqooba/go-common/version.BuildDate=${BUILD_DATE} \
              -X github.com/sqooba/go-common/version.Version=${VERSION}" \
    .

###
# Note: debian:bullseye is used because yara has a dependency on
FROM debian:bullseye

RUN apt update && apt install -y libssl1.1 libmagic-dev

COPY --from=build /usr/local/lib /usr/local/lib
COPY --from=build /usr/local/include /usr/local/include
COPY --from=build /usr/local/bin /usr/local/bin
COPY --from=build /src/yara-rest-api /yara-rest-api

RUN ldconfig

ENTRYPOINT ["/yara-rest-api"]
