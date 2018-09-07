;;; This file is part of GNUnet.
;;; Copyright (C) 2016, 2017, 2018 GNUnet e.V.
;;;
;;; GNUnet is free software; you can redistribute it and/or modify
;;; it under the terms of the GNU General Public License as published
;;; by the Free Software Foundation; either version 3, or (at your
;;; option) any later version.
;;;
;;; GNUnet is distributed in the hope that it will be useful, but
;;; WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;;; General Public License for more details.
;;;
;;; You should have received a copy of the GNU General Public License
;;; along with GNUnet; see the file COPYING.  If not, write to the
;;; Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
;;; Boston, MA 02110-1301, USA.

(use-modules
 (ice-9 popen)
 (ice-9 match)
 (ice-9 rdelim)
 (guix packages)
 (guix build-system gnu)
 (guix gexp)
 ((guix build utils) #:select (with-directory-excursion))
 (guix git-download)
 (guix utils) ; current-source-directory
 (gnu packages)
 (gnu packages aidc)
 (gnu packages autotools)
 (gnu packages backup)
 (gnu packages base)
 (gnu packages compression)
 (gnu packages curl)
 (gnu packages databases)
 (gnu packages file)
 (gnu packages gettext)
 (gnu packages glib)
 (gnu packages gnome)
 (gnu packages gnunet)
 (gnu packages gnupg)
 (gnu packages gnuzilla)
 (gnu packages groff)
 (gnu packages gstreamer)
 (gnu packages gtk)
 (gnu packages guile)
 (gnu packages image)
 (gnu packages image-viewers)
 (gnu packages libidn)
 (gnu packages libunistring)
 (gnu packages linux)
 (gnu packages maths)
 (gnu packages multiprecision)
 (gnu packages perl)
 (gnu packages pkg-config)
 (gnu packages pulseaudio)
 (gnu packages python)
 (gnu packages tex)
 (gnu packages texinfo)
 (gnu packages tex)
 (gnu packages tls)
 (gnu packages upnp)
 (gnu packages video)
 (gnu packages web)
 (gnu packages xiph)
 (ports app-text mandoc mandoc)
 (ports app-text texi2mdoc texi2mdoc)
 ((guix licenses) #:prefix license:))

(define %source-dir (current-source-directory))

(define gnunet-dev-env
  (let* ((revision "1")
         (select? (delay (or (git-predicate
                              (current-source-directory))
                             source-file?))))
    (package
      (inherit gnunet)
      (name "gnunet")
      (version (string-append "git" revision))
      (source
       (local-file
        (string-append (getcwd))
        #:recursive? #t))
      (inputs
       `(("glpk" ,glpk)
         ("gnurl" ,gnurl)
         ("gstreamer" ,gstreamer)
         ("gst-plugins-base" ,gst-plugins-base)
         ("gnutls/dane" ,gnutls/dane)
         ("iptables" ,iptables)
         ("libextractor" ,libextractor)
         ("libgcrypt" ,libgcrypt)
         ("libidn" ,libidn)
         ("libmicrohttpd" ,libmicrohttpd)
         ("libltdl" ,libltdl)
         ("libunistring" ,libunistring)
         ("openssl" ,openssl)
         ("opus" ,opus)
         ("pulseaudio" ,pulseaudio)
         ("sqlite" ,sqlite)
         ("postgresql" ,postgresql)
         ("mariadb" ,mariadb)
         ("zlib" ,zlib)
         ("perl" ,perl)
         ("python-2" ,python-2) ; tests and gnunet-qr
         ("jansson" ,jansson)
         ("nss" ,nss)
         ("glib" ,glib "bin")
         ("gmp" ,gmp)
         ("bluez" ,bluez) ; for optional bluetooth feature
         ("glib" ,glib)
         ;; ("texlive" ,texlive) ;FIXME: minimize.
         ("texlive-tiny" ,texlive-tiny) ;; Seems to be enough for _just_ info output.
         ("miniupnpc" ,miniupnpc)
         ("libogg" ,libogg)))
      (native-inputs
       `(("pkg-config" ,pkg-config)
         ("autoconf" ,autoconf)
         ("automake" ,automake)
         ("gnu-gettext" ,gnu-gettext)
         ("which" ,which)
         ("mandoc" ,mandoc)
         ("texi2mdoc" ,texi2mdoc)
         ("texinfo" ,texinfo-5) ; Debian stable: 5.2
         ("libtool" ,libtool)))
      (outputs '("out" "debug"))
      ;;#:configure-flags
      ;;(list (string-append "--with-nssdir=" %output "/lib")
      ;;"--enable-gcc-hardening"
      ;;"--enable-linker-hardening"
      ;;;;"--enable-documentation-only")
      ;;;"--enable-logging=verbose"
      ;;;"CFLAGS=-ggdb -O0")
      (arguments
       `(#:configure-flags (list "--enable-section7")
         #:phases
         ;; swap check and install phases and set paths to installed bin
         (modify-phases %standard-phases
           (add-after 'unpack 'patch-bin-sh
             (lambda _
               (for-each (lambda (f) (chmod f #o755))
                         (find-files "po" ""))
               #t))
           (add-after 'patch-bin-sh 'bootstrap
             (lambda _
               (invoke "sh" "bootstrap")))
           (add-after 'build 'install-section7
             (lambda _
               (with-directory-excursion "doc/documentation"
                 (invoke "make" "gnunet-c-tutorial.7")
                 (invoke "make" "gnunet-documentation.7")
                 (mkdir-p (string-append (assoc-ref %outputs "out")
                                         "/share/man/man7"))
                 (copy-file "../man/gnunet-c-tutorial.7"
                            (string-append (assoc-ref %outputs "out")
                                           "/share/man/man7/gnunet-c-tutorial.7"))
                 (copy-file "../man/gnunet-documentation.7"
                            (string-append (assoc-ref %outputs "out")
                                         "/share/man/man7/gnunet-documentation.7")))))
           ;;(add-before 'build 'chdir
           ;; (lambda _
           ;;  (chdir "doc/documentation")))
           (delete 'check)))))))
;; XXX: https://gnunet.org/bugs/view.php?id=4619
                             

gnunet-dev-env
