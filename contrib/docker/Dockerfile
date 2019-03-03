FROM ubuntu:18.04

ENV DEBIAN_FRONTEND noninteractive

# Install tools and dependencies
RUN apt-get update && \
    apt-get -y install --no-install-recommends \
      ca-certificates \
      libsasl2-modules \
      git \
      automake \
      autopoint \
      autoconf \
      texinfo \
      libtool \
      libltdl-dev \
      libgpg-error-dev \
      libidn11-dev \
      libunistring-dev \
      libglpk-dev \
      libbluetooth-dev \
      libextractor-dev \
      libmicrohttpd-dev \
      libgnutls28-dev \
      libgcrypt20-dev \
      libpq-dev \
      libsqlite3-dev \
      wget && \
    apt-get clean all && \
    apt-get -y autoremove && \
    rm -rf \
      /var/lib/apt/lists/* \
      /tmp/*

# Install GNUrl
ENV GNURL_VERSION=7.57.0

RUN wget -O /tmp/gnurl.tar.xz https://ftpmirror.gnu.org/gnu/gnunet/gnurl-${GNURL_VERSION}.tar.xz
RUN cd /tmp && \
      tar xvf gnurl.tar.xz && \
      cd gnurl-${GNURL_VERSION} && \
      autoreconf -i && \
      ./configure \
        --enable-ipv6 \
        --with-gnutls \
        --without-libssh2 \
        --without-libmetalink \
        --without-winidn \
        --without-librtmp \
        --without-nghttp2 \
        --without-nss \
        --without-cyassl \
        --without-polarssl \
        --without-ssl \
        --without-winssl \
        --without-darwinssl \
        --disable-sspi \
        --disable-ntlm-wb \
        --disable-ldap \
        --disable-rtsp \
        --disable-dict \
        --disable-telnet \
        --disable-tftp \
        --disable-pop3 \
        --disable-imap \
        --disable-smtp \
        --disable-gopher \
        --disable-file \
        --disable-ftp \
        --disable-smb && \
      make install && \
    cd - && \
    rm -rf /tmp/gnurl*

# Install GNUnet
ENV GNUNET_PREFIX /usr/local/gnunet
ENV CFLAGS '-g -Wall -O0'

COPY . /gnunet

RUN cd /gnunet && \
      ./bootstrap && \
      ./configure \
        --with-nssdir=/lib \
        --prefix="$GNUNET_PREFIX" \
        --enable-logging=verbose && \
      make -j3 && \
      make install && \
      ldconfig && \
    cd - && \
    rm -fr /gnunet

# Configure GNUnet
COPY ./contrib/docker/gnunet.conf /etc/gnunet.conf
COPY ./contrib/docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint
RUN chmod 755 /usr/local/bin/docker-entrypoint

ENV LOCAL_PORT_RANGE='40001 40200'
ENV PATH "$GNUNET_PREFIX/bin:/usr/local/bin:$PATH"

ENTRYPOINT ["docker-entrypoint"]
