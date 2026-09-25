FROM golang:1.26 AS builder
WORKDIR /code
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /domain_exporter \
    .

FROM gcr.io/distroless/static-debian12:nonroot
EXPOSE 9222
COPY --from=builder /domain_exporter /usr/bin/domain_exporter
USER nonroot:nonroot
ENTRYPOINT ["/usr/bin/domain_exporter"]
