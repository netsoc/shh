FROM alpine:3.12 AS builder
ARG NSJAIL_VERSION

RUN apk --no-cache add git build-base pkgconfig flex bison linux-headers bsd-compat-headers protobuf-dev libnl3-dev

RUN git clone https://github.com/google/nsjail && \
    cd nsjail/ && \
    git checkout "$NSJAIL_VERSION" && \
    make -j$(nproc)


FROM alpine:3.12

RUN apk --no-cache add libstdc++ libnl3 protobuf

COPY --from=builder /nsjail/nsjail /usr/sbin/nsjail
