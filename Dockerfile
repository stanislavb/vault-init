FROM golang:1.12
WORKDIR /build
COPY . .
RUN CGO_ENABLE=0 GOOS=linux go build -o vault-init -v .
FROM launcher.gcr.io/google/debian9:latest
COPY --from=0 /build/vault-init .
ENTRYPOINT ["/vault-init"]
