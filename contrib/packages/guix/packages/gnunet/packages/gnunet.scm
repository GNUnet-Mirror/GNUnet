;;; This file is part of GNUnet.
;;; Copyright (C) 2016, 2017 GNUnet e.V.
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

(define-module (gnunet packages gnunet)
  #:use-module (guix build-system gnu)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (gnu packages)
  #:use-module (gnu packages admin)
  #:use-module (gnu packages aidc)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages bison)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages gnunet)
  #:use-module (gnu packages gnupg)
  #:use-module (gnu packages gnuzilla)
  #:use-module (gnu packages gstreamer)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages libidn)
  #:use-module (gnu packages libunistring)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages man)
  #:use-module (gnu packages image-viewers)
  #:use-module (gnu packages maths)
  #:use-module (gnu packages multiprecision)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages pcre)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages pulseaudio)
  #:use-module (gnu packages python)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages tex)
  #:use-module (gnu packages upnp)
  #:use-module (gnu packages web)
  #:use-module (gnu packages xiph))

;; TODO: Use HEAD without checking sum of it.
;; Explanation for name scheme: UNIXPATH is capped at 108 characters,
;; this causes lots of tests to fail.
(define-public gnunetg
  (let* ((commit "b005d5e4dac03fcfdabf0d0de434da3b295f6d63")
         (revision "30"))
    (package
      (inherit gnunet)
      (name "gnunetg")
      (version (string-append "0.10.1" "-" revision
                              "." (string-take commit 7)))
      (source
       (origin
         (method git-fetch)
         (uri (git-reference
               (url "https://gnunet.org/git/gnunet.git")
               (commit commit)))
         (file-name (string-append name "-" version "-checkout"))
         (sha256
          (base32
           "0r6blgra4s4zknmxv9im3wg0q08pg2kvhq0lfir49fg1wgfk0dqj"))))
      (build-system gnu-build-system)
      (inputs
       `(("glpk" ,glpk)
         ("gnurl" ,gnurl)
         ("gstreamer" ,gstreamer)
         ("gst-plugins-base" ,gst-plugins-base)
         ("gnutls" ,gnutls)
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
         ("zlib" ,zlib)
         ("perl" ,perl)
         ("python" ,python-2) ; tests and gnunet-qr
         ("jansson" ,jansson)
         ("ncurses" ,ncurses)
         ("nss" ,nss)
         ("gmp" ,gmp)
         ("miniupnpc" ,miniupnpc)
         ("bluez" ,bluez) ; for optional bluetooth feature
         ("glib" ,glib)
         ;; ("texlive-minimal" ,texlive-minimal) ; optional.
         ("libogg" ,libogg)))
      (native-inputs
       `(("pkg-config" ,pkg-config)
         ("autoconf" ,autoconf)
         ("automake" ,automake)
         ("gnu-gettext" ,gnu-gettext)
         ("texinfo" ,texinfo)
         ("libtool" ,libtool)))
      (outputs '("out" "debug"))
      (arguments
       `(#:configure-flags
         (list (string-append "--with-nssdir=" %output "/lib")
               "--enable-experimental")
         #:parallel-tests? #f ; parallel building is not functional
         #:tests? #f ; FAIL: test_gnunet_statistics.py
         #:phases
         ;; swap check and install phases and set paths to installed bin
         (modify-phases %standard-phases
           (add-after 'unpack 'patch-bin-sh
             (lambda _
               (substitute* "bootstrap"
                 (("contrib/pogen.sh") "sh contrib/pogen.sh"))
               (for-each (lambda (f) (chmod f #o755))
                         (find-files "po" ""))
             #t))
           (add-after 'patch-bin-sh 'bootstrap
             (lambda _
               (zero? (system* "sh" "bootstrap"))))
           ;; DISABLED until failing testcases are fixed.
           ;; this test fails in our environment, disable it:
           ;; XXX: specify which ones fail.
           ;; (add-after 'patch-bin-sh 'disable-test_quota_compliance_tcp_asymmetric
           ;;   (lambda _
           ;;     (substitute* '("src/transport/Makefile.am")
           ;;       (("test_quota_compliance_tcp_asymmetric") ""))))
           ;;       (("test_quota_compliance_http_asymmetric") "")
           ;;       (("test_quota_compliance_https_asymmetric") "")
           ;;       (("test_quota_compliance_unix") "")
           ;;       (("test_quota_compliance_unix_asymmetric") ""))))
           ;; check is between build and install, fix this to:
           ;; build - install - check, else the test suite fails.
           (delete 'check)))))))
           ;; (add-after 'install 'set-path-for-check
           ;;   (lambda* (#:key outputs #:allow-other-keys)
           ;;     (let* ((out (assoc-ref outputs "out"))
           ;;            (bin (string-append out "/bin"))
           ;;            (lib (string-append out "/lib")))
           ;;       (setenv "GNUNET_PREFIX" lib)
           ;;       (setenv "PATH" (string-append (getenv "PATH") ":" bin))
           ;;       ;; XXX: https://gnunet.org/bugs/view.php?id=4619#c11061
           ;;       ;; Enable core dump before the tests.
           ;;       ;; XXX: HOW??? ulimit -c unlimited
           ;;       (zero? (system* "make" "check"))))))))

(define-public gnunet-doc
  (package
    (name "gnunet-doc")
    (version (package-version gnunetg))
    (source (package-source gnunetg))
    (build-system gnu-build-system)
    ;; FIXME: Introduce DOCS_ONLY option for configure script.
    ;; This should prevent the checks for all required software.
    (inputs
     `(("glpk" ,glpk)
       ("gnurl" ,gnurl)
       ("gstreamer" ,gstreamer)
       ("gst-plugins-base" ,gst-plugins-base)
       ("gnutls" ,gnutls)
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
       ("zlib" ,zlib)
       ("perl" ,perl)
       ("python" ,python-2) ; tests and gnunet-qr
       ("jansson" ,jansson)
       ("ncurses" ,ncurses)
       ("nss" ,nss)
       ("gmp" ,gmp)
       ("miniupnpc" ,miniupnpc)
       ("bluez" ,bluez) ; for optional bluetooth feature
       ("glib" ,glib)
       ("texlive" ,texlive) ;TODO: Use a minimal subset.
       ("libogg" ,libogg)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("autoconf" ,autoconf)
       ("automake" ,automake)
       ("gnu-gettext" ,gnu-gettext)
       ("texinfo" ,texinfo)
       ("libtool" ,libtool)))
    (arguments
     `(#:tests? #f ;Don't run tests
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-bin-sh
           (lambda _
             (substitute* "bootstrap"
               (("contrib/pogen.sh") "sh contrib/pogen.sh"))
             (for-each (lambda (f) (chmod f #o755))
                       (find-files "po" ""))
             #t))
         (add-after 'patch-bin-sh 'bootstrap
           (lambda _
             (zero? (system* "sh" "bootstrap"))))
         (replace 'build
           (lambda _
             (chdir "doc")
             (zero? (system* "make" "doc-all-give-me-the-noise"))))
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (doc (string-append out "/share/doc/gnunet")))
               (mkdir-p doc)
               (mkdir-p (string-append doc "/gnunet"))
               (install-file "gnunet.pdf" doc)
               (install-file "gnunet.info" doc)
               (copy-recursively "gnunet"
                                 (string-append doc
                                                "/gnunet")))
             #t)))))
    (synopsis "GNUnet documentation")
    (description
     "Gnunet-doc builds the documentation of GNUnet.")
    (home-page "https://gnunet.org")
    (license (package-license gnunet))))

(define-public gnunetgpg
  (package
    (inherit gnunetg)
    (name "gnunetgpg")
    (inputs
     `(("postgresql" ,postgresql)
       ,@(package-inputs gnunetg)))
    (synopsis "gnunet, variant with postgres")))

(define-public gnunetgf
  (package
    (inherit gnunetg)
    (name "gnunetgf")
    (inputs
     `(("postgresql" ,postgresql)
       ("mysql" ,mysql)
       ,@(package-inputs gnunetg)))
    (arguments
     `(#:configure-flags
       (list (string-append "--with-nssdir=" %output "/lib")
             "--enable-gcc-hardening"
             "--enable-linker-hardening"

             "--enable-poisoning"
             "--enable-sanitizer"
             "--enable-experimental"
             "--enable-logging=verbose"
             "CFLAGS=-ggdb -O0")
       #:parallel-tests? #f ; parallel building is not supported.
       ;;#:tests? #f ; fail: test_gnunet_statistics.py
       #:phases
       ;; swap check and install phases and set paths to installed bin
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-bin-sh
           (lambda _
             (substitute* "bootstrap"
               (("contrib/pogen.sh") "sh contrib/pogen.sh"))
             (for-each (lambda (f) (chmod f #o755))
                       (find-files "po" ""))
             #t))
         (add-after 'patch-bin-sh 'bootstrap
           (lambda _
             (zero? (system* "sh" "bootstrap"))))
         (delete 'check))))
    (synopsis "gnunet, full git build without tests")))

;; A package to run the test suite.
(define-public gnunetgft
  (package
    (inherit gnunetg)
    (name "gnunetgft")
    (arguments
     `(#:configure-flags
       (list (string-append "--with-nssdir=" %output "/lib")
             "--enable-gcc-hardening"
             "--enable-linker-hardening"

             ;;"--enable-poisoning"
             ;;"--enable-sanitizer"
             "--enable-experimental"
             "--enable-logging=verbose"
             "CFLAGS=-ggdb -O0")
       ;; #:parallel-tests? #f ; parallel building seems to fail
       ;;#:tests? #f ; fail: test_gnunet_statistics.py
       #:phases
       ;; swap check and install phases and set paths to installed bin
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-bin-sh
           (lambda _
             (substitute* "bootstrap"
               (("contrib/pogen.sh") "sh contrib/pogen.sh"))
             (for-each (lambda (f) (chmod f #o755))
                       (find-files "po" ""))
             #t))
         (add-after 'patch-bin-sh 'bootstrap
           (lambda _
             (zero? (system* "sh" "bootstrap"))))
         (delete 'check)
         ;; XXX: https://gnunet.org/bugs/view.php?id=4619
         (add-after 'install 'set-path-for-check
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (bin (string-append out "/bin"))
                    (lib (string-append out "/lib")))
               (setenv "GNUNET_PREFIX" lib)
               (setenv "PATH" (string-append (getenv "PATH") ":" bin))
               (zero? (system* "make" "check"))))))))
    (synopsis "gnunet, full git with tests enabled with parallel tests")))

;; ... and one package to test the package with "parallel-tests? #f"
(define-public gnunetgftn
  (package
    (inherit gnunetg)
    (name "gnunetgftn")
    (arguments
     `(#:configure-flags
       (list (string-append "--with-nssdir=" %output "/lib")
             "--enable-gcc-hardening"
             "--enable-linker-hardening"

             "--enable-poisoning"
             "--enable-sanitizer"
             "--enable-experimental"
             "--enable-logging=verbose"
             "CFLAGS=-ggdb"); -O0")
       #:parallel-tests? #f ; parallel building seems to fail
       ;;#:tests? #f ; fail: test_gnunet_statistics.py
       #:phases
       ;; swap check and install phases and set paths to installed bin
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-bin-sh
           (lambda _
             (substitute* "bootstrap"
               (("contrib/pogen.sh") "sh contrib/pogen.sh"))
             (for-each (lambda (f) (chmod f #o755))
                       (find-files "po" ""))
             #t))
         (add-after 'patch-bin-sh 'bootstrap
           (lambda _
             (zero? (system* "sh" "bootstrap"))))
         (delete 'check)
         ;; XXX: https://gnunet.org/bugs/view.php?id=4619
         (add-after 'install 'set-path-for-check
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (bin (string-append out "/bin"))
                    (lib (string-append out "/lib")))
               (setenv "GNUNET_PREFIX" lib)
               (setenv "PATH" (string-append (getenv "PATH") ":" bin))
               (zero? (system* "make" "check"))))))))))

(define-public gnunet-gtkg
  (let* ((commit "087f8e166ee6d1fc59a6bd5d05f656528761ede7")
         (revision "5"))
    (package
      (inherit gnunetgf)
      (name "gnunet-gtkg")
      (version (package-version gnunetgf))
      (source
       (origin
         (method git-fetch)
         (uri (git-reference
               (url "https://gnunet.org/git/gnunet-gtk.git")
               (commit commit)))
         (file-name (string-append name "-" version "-checkout"))
         (sha256
          (base32
            "1k03d8l0yz4fpliy5bg5s7qkpidzd6ryr4cd63wgmd227p32i87q"))))
      (arguments
       `(#:configure-flags
         (list "--with-libunique"
               "--with-qrencode"
               (string-append "--with-gnunet="
                              (assoc-ref %build-inputs "gnunetgf")))
         #:phases
         (modify-phases %standard-phases
           (add-before 'configure 'bootstrap
             (lambda _
               (zero? (system* "autoreconf" "-vfi")))))))
      (inputs
       `(("gnunetgf" ,gnunetgf)
         ("gsettings-desktop-schemas" ,gsettings-desktop-schemas)
         ("gnutls" ,gnutls)
         ("libgcrypt" ,libgcrypt)
         ("gtk+" ,gtk+)
         ("libextractor" ,libextractor)
         ("glade3" ,glade3)
         ("qrencode" ,qrencode)
         ("libunique" ,libunique)))
      (native-inputs
       `(("pkg-config" ,pkg-config)
         ("libglade" ,libglade)
         ("autoconf" ,autoconf)
         ("gnu-gettext" ,gnu-gettext)
         ("texinfo" ,texinfo)
         ("automake" ,automake)
         ("libtool" ,libtool)))
      (synopsis "Graphical front-end tools for GNUnet")
      (home-page "https://gnunet.org"))))

;; fuse, pointing to the tests disabled version of gnunet-git
(define-public gnunet-fuse-git
  (let* ((commit "3503aeff6db6b39b85e13f9483d46d49ce9cec55")
         (revision "3"))
    (package
      (inherit gnunetg)
      ;;(inherit gnunet)
      (name "gnunet-fuse-git")
      (version (package-version gnunetgf))
      ;;(version (package-version gnunet))
      (source
       (origin
         (method git-fetch)
         (uri (git-reference
               (url "https://gnunet.org/git/gnunet-fuse.git")
               (commit commit)))
         (file-name (string-append name "-" version "-checkout"))
         (sha256
          (base32
           "0sxzppanw2nrjqv1vnyj2jx3ja6gqrg0ibkl5n1fr265cqk5hgc5"))))
      (arguments
       `(#:configure-flags
         (list "--with-qrencode"
               (string-append "--with-gnunet="
                              (assoc-ref %build-inputs "gnunetgf"))) ;"gnunet")))
         #:phases
         (modify-phases %standard-phases
           (add-after 'unpack 'fix-gnunet-include-path
             (lambda _
               (substitute* "configure.ac"
                 (("gnunet/gnunet_util_lib.h")
                  "${lookin}/include/gnunet/gnunet_util_lib.h"))
               #t))
           (add-before 'configure 'bootstrap
             (lambda _
               (zero? (system* "autoreconf" "-vfi")))))))
      (inputs
       `(("gnunetgf" ,gnunetgf)))
       ;;`(("gnunet" ,gnunet)))
      (native-inputs
       `(("pkg-config" ,pkg-config)
         ("fuse" ,fuse)
         ("autoconf" ,autoconf)
         ("gnu-gettext" ,gnu-gettext)
         ("automake" ,automake)
         ("libtool" ,libtool)))
      (synopsis "FUSE for GNUnet")
      (home-page "https://gnunet.org"))))
