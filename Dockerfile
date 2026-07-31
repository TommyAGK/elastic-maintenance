FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN go build -o /out/elastic-maintenance ./cmd/elastic-maintenance

FROM gcr.io/distroless/base-debian12
COPY --from=build /out/elastic-maintenance /usr/local/bin/elastic-maintenance
ENTRYPOINT ["/usr/local/bin/elastic-maintenance"]

