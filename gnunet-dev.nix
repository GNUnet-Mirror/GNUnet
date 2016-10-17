{ stdenv, makeWrapper, pkgconfig, autoconf, automake, ccache, ccache_dir ? ""
, adns, curl, gettext, gmp, gnutls, gss, ncurses, openldap
, jansson, zlib, sqlite, mariadb, postgresql
, libextractor, libgcrypt, libgnurl, libidn, libmicrohttpd
, libpsl, libtool, libunistring, libxml2
}:

stdenv.mkDerivation rec {
  src = ./.;
  name = "gnunet-dev";

  buildInputs = [
    makeWrapper pkgconfig autoconf automake ccache
    adns curl gettext gmp gnutls gss ncurses openldap
    jansson zlib sqlite mariadb postgresql
    libextractor libgcrypt libgnurl libidn libmicrohttpd
    libpsl libtool libunistring libxml2
  ];

  patchPhase = ''
    if [ -e Makefile ]; then
      make distclean
    fi
  '';

  NIX_CFLAGS_COMPILE = "-ggdb -O0";

  configureFlags = [
    "--enable-gcc-hardening"
    "--enable-linker-hardening"

    "--enable-experimental"
    "--enable-logging=verbose"
    "--enable-poisoning"
  ];

  preConfigure = ''
    ./bootstrap
    configureFlags="$configureFlags --with-nssdir=$out/lib"

    if [ -n "${ccache_dir}" ]; then
      export CC='ccache gcc'
      export CCACHE_COMPRESS=1
      export CCACHE_DIR="${ccache_dir}"
      export CCACHE_UMASK=007
    fi
  '';

  doCheck = false;

  postInstall = ''
    # Tests can be run this way
    #export GNUNET_PREFIX="$out"
    #export PATH="$out/bin:$PATH"
    #make -k check
  '';

  meta = with stdenv.lib; {
    description = "GNU's decentralized anonymous and censorship-resistant P2P framework";

    longDescription = ''
      GNUnet is a framework for secure peer-to-peer networking that
      does not use any centralized or otherwise trusted services.  A
      first service implemented on top of the networking layer
      allows anonymous censorship-resistant file-sharing.  Anonymity
      is provided by making messages originating from a peer
      indistinguishable from messages that the peer is routing.  All
      peers act as routers and use link-encrypted connections with
      stable bandwidth utilization to communicate with each other.
      GNUnet uses a simple, excess-based economic model to allocate
      resources.  Peers in GNUnet monitor each others behavior with
      respect to resource usage; peers that contribute to the
      network are rewarded with better service.
    '';

    homepage = https://gnunet.org/;

    license = licenses.gpl3Plus;
    platforms = platforms.gnu;
    maintainers = with maintainers; [ ];
  };
}
