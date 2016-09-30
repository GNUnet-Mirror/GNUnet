# Nix package for GNUnet development
#
## INSTALL
#
# To build and install the package in the user environment, use:
#
# $ nix-env -f . -i
#
## BUILD ONLY
#
# To build the package and add it to the nix store, use:
#
# $ nix-build
#
## SHELL
#
# To launch a shell with all dependencies installed in the environment, use one of the following:
#    $ nix-shell
#
# After entering nix-shell, build it:
#
# $ configurePhase
# $ buildPhase
#
## NIXPKGS
#
# For all of the above commands, nixpkgs to use can be set the following way:
#
# a) by default it uses nixpkgs pinned to a known working version
#
# b) use nixpkgs from the system:
#    --arg pkgs 0
#
# c) use nixpkgs at a given path
#    --arg pkgs /path/to/nixpkgs
#

{ pkgs ? null }:

let
  syspkgs = import <nixpkgs> { };
  pinpkgs = syspkgs.fetchFromGitHub {
    owner = "NixOS";
    repo = "nixpkgs";

    # binary cache exists for revisions in https://nixos.org/releases/nixos/<release>/<build>/git-revision
    rev = "c4469edac1fc1fa5e5b5aa2ceadeda8f3f92d30a"; # https://nixos.org/releases/nixos/16.09/nixos-16.09beta430.c4469ed/git-revision
    sha256 = "1x6hmf815d5anfxrxl6iivfkk60q5qxa6waa9xnwhwkbc14rhvn9";
  };
  usepkgs = if null == pkgs then
             import pinpkgs {}
           else
             if 0 == pkgs then
               import <nixpkgs> { }
             else
               import pkgs {};

in with usepkgs; usepkgs.stdenv.mkDerivation rec {
  src = ./.;
  name = "gnunet-dev";

  buildInputs = [
    makeWrapper pkgconfig
    adns curl gettext gmp gnutls gss ncurses openldap zlib sqlite mariadb postgresql
    libextractor libgcrypt libgnurl libidn libmicrohttpd
    libpsl libtool libunistring libxml2
  ];

  patchPhase = ''
    test -e Makefile && make distclean
  '';

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

    homepage = http://gnunet.org/;

    license = licenses.gpl3Plus;
    platforms = platforms.gnu;
    maintainers = with maintainers; [ ];
  };
}
