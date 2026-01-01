FROM alpine:latest AS builder

WORKDIR /tmp/tzsp2pcap

COPY . .

RUN apk add --no-cache alpine-sdk libpcap-dev && \
    make tzsp2pcap

FROM alpine:latest

RUN apk add --no-cache libpcap tzdata su-exec shadow && \
    addgroup -S tzsp2pcap && \
    adduser -S tzsp2pcap -G tzsp2pcap && \
    mkdir -p /data && \
    chown tzsp2pcap:tzsp2pcap /data

COPY --from=builder /tmp/tzsp2pcap/tzsp2pcap /usr/bin
COPY docker-entrypoint.sh /usr/local/bin

RUN chmod +x /usr/local/bin/docker-entrypoint.sh

VOLUME /data

EXPOSE 37008/udp

WORKDIR /data

ENTRYPOINT ["docker-entrypoint.sh"]

CMD ["tzsp2pcap", "-p", "37008", "-o", "%Y-%m-%d_%H-%M-%S.pcap", "-G", "600"]
