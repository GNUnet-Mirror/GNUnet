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
## CCACHE
#
# To enable ccache, use the following:
#
#    --argstr ccache_dir /var/cache/ccache

# or when using nix-shell:
#    --argstr ccache_dir ~/.ccache
#
# and make sure the given directory is writable by the nixpkgs group when using nix-build or nix-env -i,
# or the current user when using nix-shell
#

{
 pkgs ? null,
 ccache_dir ? "",
}:

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
  stdenv = usepkgs.stdenvAdapters.keepDebugInfo usepkgs.stdenv;

in {
  gnunet-dev = usepkgs.callPackage ./gnunet-dev.nix {
    inherit ccache_dir;
  };
}
