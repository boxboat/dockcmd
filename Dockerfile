ARG VERSION=develop
ARG GO_VERSION=1.23.4

FROM --platform=${BUILDPLATFORM} golang:${GO_VERSION}-alpine as build

RUN apk --no-cache add make ca-certificates
RUN adduser -D dockcmd
WORKDIR /src
COPY go.mod go.sum /src/
RUN go mod download
COPY . /src/
ARG TARGETOS
ARG TARGETARCH
ARG VERSION
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} VERSION=${VERSION} make build
USER dockcmd
ENTRYPOINT [ "/src/bin/dockcmd" ]

FROM --platform=${TARGETPLATFORM} gcr.io/distroless/static as release

COPY --from=build /etc/passwd /etc/group /etc/
COPY --from=build /src/bin/dockcmd /bin/dockcmd
USER dockcmd
ENTRYPOINT [ "/bin/dockcmd" ]
