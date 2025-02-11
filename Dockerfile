FROM golang:1.23 AS builder

WORKDIR /go/src/app
ADD . /go/src/app

RUN go get -v ./...

ENV CGO_ENABLED=0
RUN go build -o /go/bin/app

FROM scratch

ARG BININFO_BUILD_DATE BININFO_COMMIT_HASH BININFO_VERSION
LABEL source_repository="https://github.com/sapcc/rabbitmq-user-credential-updater" \
  org.opencontainers.image.url="https://github.com/sapcc/rabbitmq-user-credential-updater" \
  org.opencontainers.image.created=${BININFO_BUILD_DATE} \
  org.opencontainers.image.revision=${BININFO_COMMIT_HASH} \
  org.opencontainers.image.version=${BININFO_VERSION}

COPY --from=builder /go/bin/app /default-user-credential-updater
ENTRYPOINT ["/default-user-credential-updater"]
