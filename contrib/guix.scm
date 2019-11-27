;;; guix.scm -- Guix package definition

(use-modules
  (guix git-download)
  (guix download)
  (guix packages)
  (guix utils)
  (guix gexp)
  (gnu packages)
  (gnu packages autotools)
  (gnu packages gettext)
  (gnu packages gnunet)
  (gnu packages image)
  (gnu packages texinfo)
  (srfi srfi-1)
  (ice-9 popen)
  (ice-9 rdelim))

(define %source-dir (dirname (dirname (current-filename))))

(define %git-commit
  (read-string (open-pipe "git show HEAD | head -1 | cut -d ' ' -f 2" OPEN_READ)))

(define-public gnunet-git
  (package
    (inherit gnunet)
    (name "gnunet")
    (version (git-version (package-version gnunet) "HEAD" %git-commit))
    (source (local-file %source-dir #:recursive? #t))
    (inputs
     `(("libjpeg" ,libjpeg)
       ,@(package-inputs gnunet)))
    (native-inputs
     `(("autoconf" ,autoconf)
       ("automake" ,automake)
       ("gettext" ,gnu-gettext)
       ("libtool" ,libtool)
       ("texinfo" ,texinfo)
       ("which" ,(@ (gnu packages base) which))
       ,@(package-native-inputs gnunet)))
    (arguments
     (substitute-keyword-arguments (package-arguments gnunet)
       ((#:phases phases)
        `(modify-phases ,phases
           (add-after 'unpack 'make-po-directory-writable
             (lambda _
               (for-each make-file-writable
                         (find-files "po" "."))
               #t))))))))

gnunet-git
