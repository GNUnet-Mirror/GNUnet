from fedora:26

# Install the required build tools
RUN dnf -y update && dnf -y install which git automake texinfo gettext-devel autoconf libtool libtool-ltdl-devel libidn-devel libunistring-devel glpk libextractor-devel libmicrohttpd-devel gnutls libgcrypt-devel jansson-devel sqlite-devel npm

WORKDIR /usr/src

# Install gnurl from source at version gnurl-7.54.0
RUN git clone https://git.taler.net/gnurl.git --branch gnurl-7.57.0
WORKDIR /usr/src/gnurl
RUN autoreconf -i
RUN ./configure --disable-ntlm-wb
RUN make install
WORKDIR /usr/src

RUN dnf -y install wget flex bison

# Install libpbc
RUN wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
RUN tar xvzpf pbc-0.5.14.tar.gz
WORKDIR /usr/src/pbc-0.5.14
RUN ./configure --prefix=/usr
RUN make install
WORKDIR /usr/src

RUN dnf -y install glib2-devel

# Install libbswabe
RUN git clone https://github.com/schanzen/libgabe.git
WORKDIR /usr/src/libgabe
RUN ./configure --prefix=/usr
RUN make install

# Install WebUI
WORKDIR /usr/src/
RUN git clone https://github.com/schanzen/gnunet-webui.git
WORKDIR /usr/src/gnunet-webui
RUN git checkout gnuidentity

RUN mkdir /usr/src/gnunet
WORKDIR /usr/src/gnunet
ADD . .
ARG NUM_JOBS
RUN ./bootstrap
RUN ./configure --prefix=/usr/local
RUN make -j$NUM_JOBS
RUN make install

RUN groupadd gnunetdns
RUN adduser --system -m --home-dir /var/lib/gnunet gnunet
RUN chown gnunet:gnunet /var/lib/gnunet
RUN echo '[arm]\nSYSTEM_ONLY = YES\nUSER_ONLY = NO\n' > /etc/gnunet.conf

ADD docker-entrypoint.sh .

CMD ["sh", "docker-entrypoint.sh"] 
