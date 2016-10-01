;;; This file is part of GNUnet.
;;; Copyright (C) 2016 GNUnet e.V.
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
;;;
;;;
;;; Author: N. Gillmann <ngillmann@runbox.com>
;;;
;;; Parts borrowed here from pubstrate
;;;
;;; Pubstrate is distributed in the hope that it will be useful, but
;;; WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;;; General Public License for more details.
;;;
;;; You should have received a copy of the GNU General Public License
;;; along with Pubstrate.  If not, see <http://www.gnu.org/licenses/>.
;;;
;;; Parts borrowed here from guile-sdl2
;;;
;;; Guile-sdl2 is distributed in the hope that it will be useful, but
;;; WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;;; General Public License for more details.
;;;
;;; You should have received a copy of the GNU Lesser General Public
;;; License along with guile-sdl2.  If not, see
;;; <http://www.gnu.org/licenses/>.

;; Guix package for GNUnet development
;;
;; INSTALL
;;
;; To build and install the package in the user environment, use:
;;
;; .. to be documented
;;
;; BUILD ONLY
;;
;; To build the package and add it to the gnu store, use:
;;
;; $ guix build -f guix.scm

(use-modules (ice-9 popen)
             (ice-9 match)
             (ice-9 rdelim)
             (guix packages)
             (guix build-system gnu)
             (guix gexp)
             ((guix build utils) #:select (with-directory-excursion))
             (gnu packages)
             (gnu packages base)
             (gnu packages gnunet)
             (gnu packages file)
             (gnu packages aidc)
             (gnu packages autotools)
             (gnu packages compression)
             (gnu packages curl)
             (gnu packages geeqie)
             (gnu packages gettext)
             (gnu packages glib)
             (gnu packages gnome)
             (gnu packages gnupg)
             (gnu packages groff)
             (gnu packages gtk)
             (gnu packages guile)
             (gnu packages gstreamer)
             (gnu packages gnuzilla)
             (gnu packages libidn)
             (gnu packages linux)
             (gnu packages image)
             (gnu packages libunistring)
             (gnu packages maths)
             (gnu packages multiprecision)
             (gnu packages pkg-config)
             (gnu packages perl)
             (gnu packages pulseaudio)
             (gnu packages python)
             (gnu packages databases)
             (gnu packages tls)
             (gnu packages tex)
             (gnu packages video)
             (gnu packages web)
             (gnu packages xiph)
             (gnu packages backup)
             ((guix licenses) #:prefix license:))


(define %source-dir (dirname (current-filename)))

(define git-file?
  (let* ((pipe (with-directory-excursion %source-dir
                 (open-pipe* OPEN_READ "svn" "ls" "-R")))
         (files (let loop ((lines '()))
                  (match (read-line pipe)
                    ((? eof-object?)
                     (reverse lines))
                    (line
                     (loop (cons line lines))))))
         (status (close-pipe pipe)))
    (lambda (file stat)
      (match (stat:type stat)
        ('directory #t)
        ((or 'regular 'symlink)
         (any (cut string-suffix? <> file) files))
        (_ #f)))))

(define gnunet-svn
  (package
    (name "gnunet-svn")
    (version (string-append "0.10.1-" "dev"))
    (source
     (local-file %source-dir
                 #:recursive? #t))
                 ;;#:select? git-file?))
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
       ("postgresql" ,postgresql)
       ("mysql" ,mysql)
       ("zlib" ,zlib)
       ("perl" ,perl)
       ("python" ,python) ; tests and gnunet-qr
       ("jansson" ,jansson)
       ("nss" ,nss)
       ("gmp" ,gmp)
       ("bluez" ,bluez) ; for optional bluetooth feature
       ("glib" ,glib)
       ;; There are currently no binary substitutes for texlive due to
       ;; its size. Uncomment if you need it.
       ;;("texlive-minimal" ,texlive-minimal) ; optional.
       ("libogg" ,libogg)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("autoconf" ,autoconf)
       ("automake" ,automake)
       ("gnu-gettext" ,gnu-gettext)
       ("libtool" ,libtool)))
    (arguments
     `(#:configure-flags
       (list (string-append "--with-nssdir=" %output "/lib")
             "--enable-experimental")
             ;; These appear to be "broken" on Guix, needs debugging.
             ;;"--enable-gcc-hardening"
             ;;"--enable-linker-hardening"
             ;;"--enable-logging=verbose")
             ;;"--enable-poisoning")
       ;;#:parallel-tests? #f ; parallel building seems to fail
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

gnunet-svn
