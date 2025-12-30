FROM alpine:latest AS builder

WORKDIR /tmp/tzsp2pcap

COPY . .

RUN apk add --no-cache alpine-sdk libpcap-dev && \
    make tzsp2pcap

FROM alpine:latest

RUN apk add --no-cache libpcap

COPY --from=builder /tmp/tzsp2pcap/tzsp2pcap /usr/bin

VOLUME /data

EXPOSE 37008/udp

WORKDIR /data

ENTRYPOINT ["tzsp2pcap", "-p", "37008", "-o", "%Y-%m-%d_%H-%M-%S.pcap"]

CMD ["-G 600"]