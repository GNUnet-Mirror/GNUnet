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
;;;

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
 (gnu packages video)
 (gnu packages web)
 (gnu packages xiph)
 ((guix licenses) #:prefix license:))

(define %source-dir (string-append (current-source-directory)
                                   "/../../../"))

(define gnunet-doc
  (let* ((revision "1")
         (select? (delay (or (git-predicate
                              (string-append (current-source-directory)
                                             "/../../../"))
                             source-file?))))
      (package
      (name "gnunet-doc")
      (version (string-append "0.10.1-" revision "." "dev"))
      (source
       (local-file ;;"../../.."
                   ;;%source-dir
                   ;;(string-append (getcwd) "/../../../")
                   (string-append (getcwd)) ;drrty hack and this assumes one static position FIXME!
                   #:recursive? #t))
                   ;;#:select? (git-predicate %source-dir)))
                   ;;#:select? (force select?)))
      (build-system gnu-build-system)
      (inputs
       `(("glpk" ,glpk)
         ("gnurl" ,gnurl)
         ("gstreamer" ,gstreamer)
         ("gst-plugins-base" ,gst-plugins-base)
         ("gnutls" ,gnutls) ;Change to gnutls/dane once it is merged.
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
         ("glib" ,glib "bin")
         ("gmp" ,gmp)
         ("bluez" ,bluez) ; for optional bluetooth feature
         ("glib" ,glib)
         ;;("texlive-minimal" ,texlive-minimal) ; optional.
         ("texlive" ,texlive)
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
           (add-after 'unpack 'autoconf
             (lambda _
               (substitute* "bootstrap"
                 (("contrib/pogen.sh") "sh contrib/pogen.sh"))
               (for-each (lambda (f) (chmod f #o755))
                         (find-files "po" ""))
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
                                                  "/gnunet"))
                 (install-file "gnunet-c-tutorial.pdf" doc)
                 (install-file "gnunet-c-tutorial.info" doc)
                 (copy-recursively "gnunet-c-tutorial"
                                   (string-append doc
                                                  "/gnunet-c-tutorial")))
               #t)))))
      (synopsis "Documentation of GNUnet")
      (description
       "GNUnet documentation build")
      (license (list license:fdl1.3+ license:gpl3+))
      (home-page "https://gnunet.org/"))))

gnunet-doc
