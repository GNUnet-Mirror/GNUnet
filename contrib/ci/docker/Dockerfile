FROM ubuntu:18.04

# Install the required build tools
RUN apt update && apt install -y apt git autopoint automake texinfo gettext autoconf libtool libidn11-dev libunistring-dev gnutls-dev libgcrypt20 libgcrypt20-dev libjansson-dev libsqlite3-dev wget flex bison libglib2.0-dev libgmp3-dev libmicrohttpd-dev libglpk-dev libextractor-dev

# Install gnurl from source at version gnurl-7.54.0
WORKDIR /usr/src
RUN git clone https://git.taler.net/gnurl.git --branch gnurl-7.57.0
RUN cd /usr/src/gnurl && autoreconf -i && ./configure --prefix=/usr --disable-ntlm-wb && make install

# Install libpbc
WORKDIR /usr/src
RUN wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && tar xvzpf pbc-0.5.14.tar.gz && cd /usr/src/pbc-0.5.14 && ./configure --prefix=/usr && make install

# Install libbswabe
WORKDIR /usr/src
RUN git clone https://github.com/schanzen/libgabe.git && cd /usr/src/libgabe && ./configure --prefix=/usr && make install

WORKDIR /usr/src
RUN git clone git://gnunet.org/gnunet.git
RUN cd /usr/src/gnunet && ./bootstrap && ./configure --enable-experimental --prefix=/usr && make && make install

RUN addgroup gnunetdns && addgroup gnunet && adduser --system --home /var/lib/gnunet gnunet
RUN chown gnunet:gnunet /var/lib/gnunet
RUN echo '[arm]\nSYSTEM_ONLY = YES\nUSER_ONLY = NO\n' > /etc/gnunet.conf

ADD docker-entrypoint.sh .

RUN rm -rf /usr/src/*
#RUN apt remove gcc

CMD ["sh", "docker-entrypoint.sh"]
