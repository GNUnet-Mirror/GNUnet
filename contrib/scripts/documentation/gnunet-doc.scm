;;; This file is part of GNUnet.
;;; Copyright (C) 2016, 2017 GNUnet e.V.
;;;
;;; GNUnet is free software: you can redistribute it and/or modify it
;;; under the terms of the GNU Affero General Public License as published
;;; by the Free Software Foundation, either version 3 of the License, or
;;; (at your option) any later version.
;;;
;;; GNUnet is distributed in the hope that it will be useful, but
;;; WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;;; Affero General Public License for more details.
;;;
;;; You should have received a copy of the GNU Affero General Public License
;;; along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
 (gnu packages graphviz)
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
 ;;(gnunet packages texlive) ;GNUnet module including texlive-2012 WIP
 ((guix licenses) #:prefix license:))

;;(define %source-dir (string-append (current-source-directory)
;;                                   "/../../../"))
(define %source-dir (dirname (current-filename)))

(define gnunet-doc
  (let* ((revision "2")
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
         ("gnutls/dane" ,gnutls/dane)
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
         ("mysql" ,mariadb)
         ("zlib" ,zlib)
         ("perl" ,perl)
         ("python-2" ,python-2) ; tests and gnunet-qr
         ("jansson" ,jansson)
         ("nss" ,nss)
         ("glib" ,glib "bin")
         ("gmp" ,gmp)
         ("bluez" ,bluez) ; for optional bluetooth feature
         ("glib" ,glib)
         ;;("texlive-minimal" ,texlive-minimal) ; optional.
         ("texlive" ,texlive) ;TODO: Stabilize Texlive-2012 package
         ("libogg" ,libogg)))
      (native-inputs
       `(("pkg-config" ,pkg-config)
         ("autoconf" ,autoconf)
         ("automake" ,automake)
         ("gnu-gettext" ,gnu-gettext)
         ("graphviz" ,graphviz) ; dot
         ("texinfo-5" ,texinfo-5) ; Debian stable
         ("which" ,which)
         ("libtool" ,libtool)))
      (arguments
       `(#:configure-flags
         (list "--enable-documentation")
         #:tests? #f ;Don't run tests
         #:phases
         (modify-phases %standard-phases
           (add-after 'unpack 'autoconf
             (lambda _
               (substitute* "bootstrap"
                 (("contrib/pogen.sh") "sh contrib/pogen.sh"))
               (for-each (lambda (f) (chmod f #o755))
                         (find-files "po" ""))
               (zero? (system* "sh" "bootstrap"))))
           (add-after 'build 'run-gendocs
             (lambda _
               (chdir "doc/documentation")
               ;;(zero? (system* "make" "dev-build"))))
               (zero? (system* "sh" "run-gendocs.sh"))))
           ;; (zero? (system* "make" "pdf"))
           ;; (zero? (system* "make" "html"))
           ;; (zero? (system* "make" "info"))))
           ;;(zero? (system* "make" "doc-all-give-me-the-noise"))))
           (replace 'install
             (lambda _
               (zero? (system* "make" "doc-gendoc-install")))))))
      ;;(lambda* (#:key outputs #:allow-other-keys)
      ;; (let* ((out (assoc-ref outputs "out"))
      ;;        (doc (string-append out "/share/doc/gnunet")))
      ;;   (mkdir-p doc)
      ;;   (copy-recursively "images"
      ;;                     (string-append doc
      ;;                                    "/images"))
      ;;   (mkdir-p (string-append doc "/gnunet"))
      ;;   (install-file "gnunet.pdf" doc)
      ;;   (install-file "gnunet.info" doc)
      ;;   (install-file "gnunet.log" doc) ;TODO: Move to 'dev' output?
      ;;   (copy-recursively "gnunet"
      ;;                     (string-append doc
      ;;                                    "/gnunet"))
      ;;   (install-file "gnunet-c-tutorial.pdf" doc)
      ;;   (install-file "gnunet-c-tutorial.info" doc)
      ;;   (install-file "gnunet-c-tutorial.log" doc) ;TODO: Move to 'dev' output?
      ;;   (copy-recursively "gnunet-c-tutorial"
      ;;                     (string-append doc
      ;;                                    "/gnunet-c-tutorial")))
      ;; #t)))))
      (synopsis "Documentation of GNUnet")
      (description
       "GNUnet documentation build")
      (license (list license:fdl1.3+ license:gpl3+))
      (home-page "https://gnunet.org/"))))

gnunet-doc
