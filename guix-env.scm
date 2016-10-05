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
;;; Parts borrowed here from pubstrate:
;;; Pubstrate is distributed in the hope that it will be useful, but
;;; WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;;; General Public License for more details.
;;;
;;; You should have received a copy of the GNU General Public License
;;; along with Pubstrate.  If not, see <http://www.gnu.org/licenses/>.
;;;
;;; Parts borrowed here from guile-sdl2:
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
;; Precondition for using this file is that you run Guix and have a
;; development setup for this setup, which involves a version of Guile in
;; your PATH.
;; Let us assume you checked out https://gnunet.org/svn/, and you exported
;; a variable named GNUNET_SVN_PATH="/home/alice/src/gnunet/svn/".
;;
;; export GNUNET_SVN_PATH="/home/alice/src/gnunet/svn/"
;;
;; A directory in GUILE_LOAD_PATH is a root, this means that the value of
;; GNUNET_SVN_PATH dictates how we call this Guix module.
;; We now have to append $GNUNET_SVN_PATH to GUILE_LOAD_PATH and are almost
;; ready to go.
;;
;; export GUILE_LOAD_PATH="/home/alice/.guix-profile/share/guile/site/2.0${GUILE_LOAD_PATH:+:}$GUILE_LOAD_PATH:$GNUNET_SVN_PATH
;;
;; Now we make use of the function of Guix to build from expressions:
;;
;; guix build --expression="(@ (gnunet guix-env) gnunet-svn)"
;;
;; This will build the public exported value gnunet-svn from this file.
;; See `info guix-build' for more about this magic.
;;
;; While this might look complicated, it adds options which will
;; be added later to this file, for example invoking a development
;; environment (guix env) etc...

(define-module (gnunet guix-env)
  #:use-modules (ice-9 popen)
  #:use-modules (ice-9 match)
  #:use-modules (ice-9 rdelim)
  #:use-modules (guix packages)
  #:use-modules (guix build-system gnu)
  #:use-modules (guix gexp)
  #:use-modules ((guix build utils) #:select (with-directory-excursion))
  #:use-modules (gnu packages)
  #:use-modules (gnu packages base)
  #:use-modules (gnu packages gnunet)
  #:use-modules (gnu packages file)
  #:use-modules (gnu packages aidc)
  #:use-modules (gnu packages autotools)
  #:use-modules (gnu packages compression)
  #:use-modules (gnu packages curl)
  #:use-modules (gnu packages geeqie)
  #:use-modules (gnu packages gettext)
  #:use-modules (gnu packages glib)
  #:use-modules (gnu packages gnome)
  #:use-modules (gnu packages gnupg)
  #:use-modules (gnu packages groff)
  #:use-modules (gnu packages gtk)
  #:use-modules (gnu packages guile)
  #:use-modules (gnu packages gstreamer)
  #:use-modules (gnu packages gnuzilla)
  #:use-modules (gnu packages libidn)
  #:use-modules (gnu packages linux)
  #:use-modules (gnu packages image)
  #:use-modules (gnu packages libunistring)
  #:use-modules (gnu packages maths)
  #:use-modules (gnu packages multiprecision)
  #:use-modules (gnu packages pkg-config)
  #:use-modules (gnu packages perl)
  #:use-modules (gnu packages pulseaudio)
  #:use-modules (gnu packages python)
  #:use-modules (gnu packages databases)
  #:use-modules (gnu packages tls)
  #:use-modules (gnu packages tex)
  #:use-modules (gnu packages video)
  #:use-modules (gnu packages web)
  #:use-modules (gnu packages xiph)
  #:use-modules (gnu packages backup)
  #:use-modules ((guix licenses) #:prefix license:))

(define %source-dir (dirname (current-filename)))

;; This will be needed when gnunet source moves to git.
;; Taken from https://gitlab.com/dustyweb/pubstrate/blob/master/guix.scm
(define git-file?
  (let* ((pipe (with-directory-excursion %source-dir
                 (open-pipe* OPEN_READ "git" "ls-files")))
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

(define-public gnunet-svn
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
       ;; There are currently no binary substitutes for texlive on
       ;; hydra.gnu.org or its mirrors due to its size. Uncomment if you need it.
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
             "--enable-experimental"
             ;; These appear to be "broken" on Guix, needs debugging.
             ;;"--enable-gcc-hardening"
             "--enable-linker-hardening"
             "--enable-logging=verbose"
             "--enable-poisoning")
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
