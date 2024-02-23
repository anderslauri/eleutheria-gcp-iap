FROM golang:1.22-alpine AS builder
RUN apk update && apk upgrade && apk add --no-cache git ca-certificates tzdata curl && update-ca-certificates
RUN curl -L -o /tmp/pkl https://github.com/apple/pkl/releases/download/0.25.2/pkl-alpine-linux-amd64
RUN mv /tmp/pkl /usr/bin/pkl && chmod +x /usr/bin/pkl && pkl --version
WORKDIR $GOPATH/src/github.com/anderslauri/open-iap
COPY . .
RUN go install github.com/apple/pkl-go/cmd/pkl-gen-go@v0.5.3 && pkl-gen-go default_config.pkl
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags timetzdata -ldflags="-w -s" -o /go/bin/open-iap

FROM golang:1.22-alpine as open-iap
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/bin/pkl /usr/bin/pkl
COPY --from=builder /go/bin/open-iap /go/open-iap
COPY app_config.pkl default_config.pkl /go/
ENTRYPOINT ["/go/open-iap"]