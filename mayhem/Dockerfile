FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential automake pkg-config libtool libsdl2-dev

COPY . /repo
WORKDIR /repo
RUN autoreconf -if
RUN ./configure --disable-sherlock --prefix=/install
RUN make -j8
RUN make install

FROM ubuntu:22.04 as package
COPY --from=builder /install /install
