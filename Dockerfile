FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN go build -o /out/elastic-maintainer ./cmd/elastic-maintainer

FROM gcr.io/distroless/base-debian12
COPY --from=build /out/elastic-maintainer /usr/local/bin/elastic-maintainer
ENTRYPOINT ["/usr/local/bin/elastic-maintainer"]

