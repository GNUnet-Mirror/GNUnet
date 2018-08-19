;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2014 Sree Harsha Totakura <sreeharsha@totakura.in>
;;; Copyright © 2015, 2017, 2018 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015, 2017 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2016 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2016, 2017, 2018 Nils Gillmann <ng0@n0.is>
;;; Copyright © 2016, 2017, 2018 Tobias Geerinckx-Rice <me@tobias.gr>
;;;
;;; This file is part of GNU Guix.
;;;
;;; GNU Guix is free software; you can redistribute it and/or modify it
;;; under the terms of the GNU General Public License as published by
;;; the Free Software Foundation; either version 3 of the License, or (at
;;; your option) any later version.
;;;
;;; GNU Guix is distributed in the hope that it will be useful, but
;;; WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;; GNU General Public License for more details.
;;;
;;; You should have received a copy of the GNU General Public License
;;; along with GNU Guix.  If not, see <http://www.gnu.org/licenses/>.

(define-module (gnu packages gnunet)
  #:use-module (ice-9 popen)
  #:use-module (ice-9 rdelim)
  #:use-module (gnu packages)
  #:use-module (gnu packages file)
  #:use-module (gnu packages base)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages aidc)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages curl)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages gnupg)
  #:use-module (gnu packages gnuzilla)
  #:use-module (gnu packages groff)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages guile)
  #:use-module (gnu packages gstreamer)
  #:use-module (gnu packages libidn)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages image)
  #:use-module (gnu packages libunistring)
  #:use-module (gnu packages maths)
  #:use-module (gnu packages multiprecision)
  #:use-module (gnu packages music)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages package-management)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pulseaudio)
  #:use-module (gnu packages python)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages video)
  #:use-module (gnu packages web)
  #:use-module (gnu packages xiph)
  #:use-module (gnu packages backup)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module ((guix build utils) #:prefix build-utils:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix utils)
  #:use-module (guix gexp)
  #:use-module (guix git-download)
  #:use-module (guix build-system gnu))


(define-public libextractor
  (package
   (name "libextractor")
   (version "1.7")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnu/libextractor/libextractor-"
                                version ".tar.gz"))
            (sha256
             (base32
              "13wf6vj7mkv6gw8h183cnk7m24ir0gyf198pyb2148ng4klgv9p0"))))
   (build-system gnu-build-system)
   ;; WARNING: Checks require /dev/shm to be in the build chroot, especially
   ;; not to be a symbolic link to /run/shm.
   ;; FIXME:
   ;; The following dependencies are all optional, but should be
   ;; available for maximum coverage:
   ;; * libmagic (file)
   ;; * librpm (rpm)    ; investigate failure
   ;; * libgif (giflib) ; investigate failure
   (inputs
    `(("exiv2" ,exiv2)
      ("bzip2" ,bzip2)
      ("flac" ,flac)
      ("ffmpeg" ,ffmpeg-3.4)
      ("file" ,file)                           ;libmagic, for the MIME plug-in
      ("glib" ,glib)
      ("gstreamer" ,gstreamer)
      ("gst-plugins-base" ,gst-plugins-base)
      ("gtk+" ,gtk+)
      ("libarchive" ,libarchive)
      ("libgsf" ,libgsf)
      ("libjpeg" ,libjpeg)
      ("libltdl" ,libltdl)
      ("libmpeg2" ,libmpeg2)
      ("libmp4v2" ,libmp4v2)
      ("libsmf" ,libsmf)
      ("tidy-html" ,tidy-html)
      ("libogg" ,libogg)
      ("libtiff" ,libtiff)
      ("libvorbis" ,libvorbis)
      ("zlib" ,zlib)))
   (native-inputs
    `(("pkg-config" ,pkg-config)))
   (outputs '("out"
              "static")) ; 396 KiB .a files
   (arguments
    `(#:configure-flags
      (list (string-append "--with-ltdl="
                           (assoc-ref %build-inputs "libltdl"))
            (string-append "--with-tidy="
                           (assoc-ref %build-inputs "tidy-html")))
      #:parallel-tests? #f
      #:phases
      (modify-phases %standard-phases
        (add-after 'install 'move-static-libraries
          (lambda* (#:key outputs #:allow-other-keys)
            ;; Move static libraries to the "static" output.
            (let* ((out    (assoc-ref outputs "out"))
                   (lib    (string-append out "/lib"))
                   (static (assoc-ref outputs "static"))
                   (slib   (string-append static "/lib")))
              (mkdir-p slib)
              (for-each (lambda (file)
                          (install-file file slib)
                          (delete-file file))
                        (find-files lib "\\.a$"))
              #t))))))
   (synopsis "Library to extract meta-data from media files")
   (description
    "GNU libextractor is a library for extracting metadata from files.  It
supports a very large number of file formats, including audio files, document
files, and archive files.  Each file format is implemented as a plugin, so
new formats can be added easily.  The package also contains a command-line
tool to extract metadata from a file and print the results.")
   (license license:gpl3+)
   (home-page "https://www.gnu.org/software/libextractor/")))

(define-public libmicrohttpd
  (package
   (name "libmicrohttpd")
   (version "0.9.59")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnu/libmicrohttpd/libmicrohttpd-"
                                version ".tar.gz"))
            (sha256
             (base32
              "0g4jgnv43yddr9yxrqg11632rip0lg5c53gmy5wy3c0i1dywv74v"))))
   (build-system gnu-build-system)
   (inputs
    `(("curl" ,curl)
      ("gnutls" ,gnutls/dane)
      ("libgcrypt" ,libgcrypt)
      ("openssl" ,openssl)
      ("zlib" ,zlib)))
   (arguments
    `(#:parallel-tests? #f
      #:phases (modify-phases %standard-phases
                 (add-before 'check 'add-missing-LDFLAGS
                   (lambda _
                     ;; The two test_upgrade* programs depend on GnuTLS
                     ;; directly but lack -lgnutls; add it.
                     (substitute* "src/microhttpd/Makefile"
                       (("^test_upgrade(.*)LDFLAGS = (.*)$" _ first rest)
                        (string-append "test_upgrade" first
                                       "LDFLAGS = -lgnutls " rest)))
                     #t)))))
   (synopsis "C library implementing an HTTP 1.1 server")
   (description
    "GNU libmicrohttpd is a small, embeddable HTTP server implemented as a
C library.  It makes it easy to run an HTTP server as part of another
application.  The library is fully HTTP 1.1 compliant.  It can listen on
multiple ports, supports four different threading models, and supports
IPv6.  It also features security features such as basic and digest
authentication and support for SSL3 and TLS.")
   (license license:lgpl2.1+)
   (home-page "https://www.gnu.org/software/libmicrohttpd/")))

(define-public gnurl
  (package
   (name "gnurl")
   (version "7.61.0")
   (source (origin
            (method url-fetch)
            (uri (string-append "mirror://gnu/gnunet/" name "-" version ".tar.Z"))
            (sha256
             (base32
              "1h03zkd9mp4xb5icirl3bfd64r5x8j9ka1hw9qd0n1ql1w0ilz23"))))
   (build-system gnu-build-system)
   (outputs '("out"
              "doc"))                             ; 1.5 MiB of man3 pages
   (inputs `(("gnutls" ,gnutls/dane)
             ("libidn" ,libidn)
             ("zlib" ,zlib)))
   (native-inputs
    `(("libtool" ,libtool)
      ("groff" ,groff)
      ("perl" ,perl)
      ("pkg-config" ,pkg-config)
      ("python" ,python-2)))
   (arguments
    `(#:configure-flags (list "--enable-benchmark")
      #:test-target "test"
      #:parallel-tests? #f
      #:phases
      ;; We have to patch runtests.pl in tests/ directory
      (modify-phases %standard-phases
        (add-after 'install 'move-man3-pages
          (lambda* (#:key outputs #:allow-other-keys)
            ;; Move section 3 man pages to "doc".
            (let ((out (assoc-ref outputs "out"))
                  (doc (assoc-ref outputs "doc")))
              (mkdir-p (string-append doc "/share/man"))
              (rename-file (string-append out "/share/man/man3")
                           (string-append doc "/share/man/man3"))
              #t)))
        (replace 'check
          (lambda _
            (substitute* "tests/runtests.pl"
              (("/bin/sh") (which "sh")))

            ;; Make test output more verbose.
            (invoke "make" "-C" "tests" "test"))))))
   (synopsis "Microfork of cURL with support for the HTTP/HTTPS/GnuTLS subset of cURL")
   (description
    "Gnurl is a microfork of cURL, a command line tool for transferring data
with URL syntax.  While cURL supports many crypto backends, libgnurl only
supports HTTP, HTTPS and GnuTLS.")
   (license (license:non-copyleft "file://COPYING"
                                  "See COPYING in the distribution."))
   (home-page "https://gnunet.org/gnurl")))


(define (repeat f n)
  (if (= n 1)
      f
      (lambda (x) (f ((repeat f (- n 1)) x)))))

(define %source-dir ((repeat dirname 5) (current-filename)))
  
(define (git-output . args)
  "Execute 'git ARGS ...' command and return its output without trailing
newspace."
  (build-utils:with-directory-excursion %source-dir
    (let* ((port   (apply open-pipe* OPEN_READ "git" args))
           (output (read-string port)))
      (close-port port)
      (string-trim-right output #\newline))))

(define (current-git-version)
  (git-output "describe" "--tags"))

(define (git-sources)
  (local-file %source-dir
	      #:recursive? #t
	      #:select? (git-predicate %source-dir)))

(define-public gnunet
  (package
   (name "gnunet")
   (version (current-git-version))
   (source (git-sources))
   (build-system gnu-build-system)
   (inputs
    `(("glpk" ,glpk)
      ("gnurl" ,gnurl)
      ("gstreamer" ,gstreamer)
      ("gst-plugins-base" ,gst-plugins-base)
      ("gnutls" ,gnutls/dane)
      ("libextractor" ,libextractor)
      ("libgcrypt" ,libgcrypt)
      ("libidn" ,libidn)
      ("libmicrohttpd" ,libmicrohttpd) ; hostlist, pt, contrib, and more
      ("libltdl" ,libltdl)
      ("libunistring" ,libunistring) ; fs and more
      ("openssl" ,openssl) ; transport, certificate creation, contribs
      ("opus" ,opus) ; gnunet-conversation
      ("pulseaudio" ,pulseaudio) ; conversation
      ("sqlite" ,sqlite) ; sqlite bindings, *store
      ("postgresql" ,postgresql)
      ("zlib" ,zlib)
      ("perl" ,perl) ; doxygen and more
      ("jansson" ,jansson) ; identity, taler (external), gnunet-json, gns
      ("nss" ,nss) ; gns
      ("gmp" ,gmp) ; util
      ("bluez" ,bluez) ; gnunet-transport
      ("glib" ,glib)
      ("libogg" ,libogg) ; gnunet-conversation
      ("python-2" ,python-2))) ; tests, gnunet-qr
   (native-inputs
    `(("pkg-config" ,pkg-config)
      ("autoconf" ,autoconf)
      ("automake" ,automake)
      ("gnu-gettext" ,gnu-gettext)
      ("which" ,which)
      ("texinfo" ,texinfo-5) ; Debian stable: 5.2
      ("libtool" ,libtool)))
   (arguments
    '(#:configure-flags
      (list (string-append "--with-nssdir=" %output "/lib"))
      #:parallel-tests? #f
      ;; test_gnunet_service_arm fails; reported upstream
      #:tests? #f
      #:phases
      (modify-phases %standard-phases
        (add-after 'unpack 'patch-bin-sh
          (lambda _
            (for-each (lambda (f) (chmod f #o755))
                      (find-files "po" ""))
            #t))
        ;; swap check and install phases and set paths to installed binaries
        (add-before 'check 'set-path-for-check
          (lambda* (#:key outputs #:allow-other-keys)
           (let ((out (assoc-ref outputs "out")))
             (setenv "GNUNET_PREFIX" (string-append out "/lib"))
             (setenv "PATH" (string-append (getenv "PATH") ":" out "/bin")))
           #t))
        (add-after 'install 'check
          (assoc-ref %standard-phases 'check))
        (delete 'check))))
   (synopsis "Secure, decentralized, peer-to-peer networking framework")
   (description
     "GNUnet is a framework for secure peer-to-peer networking.  The
high-level goal is to provide a strong foundation of free software for a
global, distributed network that provides security and privacy.  GNUnet in
that sense aims to replace the current internet protocol stack.  Along with
an application for secure publication of files, it has grown to include all
kinds of basic applications for the foundation of a GNU internet.")
   (license license:gpl3+)
   (home-page "https://gnunet.org/")))

(define-public guile-gnunet                       ;GSoC 2015!
  (let ((commit "383eac2aab175d8d9ea5315c2f1c8a5055c76a52"))
    (package
      (name "guile-gnunet")
      (version (string-append "0.0." (string-take commit 7)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://git.savannah.gnu.org/git/guix/gnunet.git/")
                      (commit commit)))
                (file-name (string-append name "-" version "-checkout"))
                (sha256
                 (base32
                  "0k6mn28isjlxrnvbnblab3nh2xqx1b7san8k98kc35ap9lq0iz8w"))))
      (build-system gnu-build-system)
      (native-inputs `(("pkg-config" ,pkg-config)
                       ("autoconf" ,autoconf-wrapper)
                       ("automake" ,automake)))
      (inputs `(("guile" ,guile-2.0)
                ("gnunet" ,gnunet)))
      (synopsis "Guile bindings for GNUnet services")
      (description
       "This package provides Guile bindings to the client libraries of various
GNUnet services, including the @dfn{identity} and @dfn{file sharing}
services.")
      (home-page "https://gnu.org/software/guix")
      (license license:gpl3+))))

;; FIXME: "gnunet-setup" segfaults under certain conditions and "gnunet-gtk"
;; does not seem to be fully functional.  This has been reported upstream:
;; http://lists.gnu.org/archive/html/gnunet-developers/2016-02/msg00004.html
(define-public gnunet-gtk
  (package (inherit gnunet)
    (name "gnunet-gtk")
    (version (package-version gnunet))
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/gnunet/gnunet-gtk-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1p38k1s6a2fmcfc9a7cf1zrdycm9h06kqdyand4s3k500nj6mb4g"))))
    (arguments
     `(#:configure-flags
       (list "--with-libunique"
             "--with-qrencode"
             (string-append "--with-gnunet="
                            (assoc-ref %build-inputs "gnunet")))))
    (inputs
     `(("gnunet" ,gnunet)
       ("libgcrypt" ,libgcrypt)
       ("gtk+" ,gtk+)
       ("libextractor" ,libextractor)
       ("glade3" ,glade3)
       ("qrencode" ,qrencode)
       ("libunique" ,libunique)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("libglade" ,libglade)))
    (synopsis "Graphical front-end tools for GNUnet")))
