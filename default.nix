{ nixpkgs ? import <nixpkgs> {} }:
nixpkgs.pkgs.callPackage ./gnunet-dev.nix { }
