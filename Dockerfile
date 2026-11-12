# Build go
FROM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS builder
WORKDIR /app
COPY . .
ENV CGO_ENABLED=0
RUN go mod download
RUN go build -v -o XrayR -tags with_quic -trimpath -ldflags "-s -w -buildid="

# Release
FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
# 安装必要的工具包
RUN apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
RUN mkdir /etc/XrayR/
COPY --from=builder /app/XrayR /usr/local/bin

ENTRYPOINT [ "XrayR", "--config", "/etc/XrayR/config.yml"]
