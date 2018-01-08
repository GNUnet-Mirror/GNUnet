* Completion Levels:

** chapters/philosophy: around 100% fixed after initial export.

* What's left to do

- Which Texlive modules are needed? Decrease the size.
  - distro specific, or can we set requirements?
- Update the content of gnunet documentation.
- XXX: images are only generated for the html documentation
  with gendoc.sh … FIXME!
- XXX: png,dot, and svg images MUST be converted to eps by the
  build system. Right now they aren't, as a result: No images.

* How to use (hack) on this

** with guix

Adjust accordingly, ie read the Guix Documentation:
setenv GUIX_PACKAGE_PATH "gnunet/contrib/packages/guix/packages"
guix environment gnunet-doc
and
guix build -f contrib/packages/guix/gnunet-doc.scm

** without guix

You need to have Texinfo and Texlive in your path.
sh bootstrap
./configure --enable-documentation
cd doc
make (format you want)

for example: make html, make info, make pdf

* structure (relations)

** gnunet.texi
 -> chapters/developer.texi
 -> chapters/installation.texi
 -> chapters/philosophy.texi
 -> chapters/user.texi
 -> chapters/vocabulary.texi
 -> images/*
 -> gpl-3.0.texi
 -> fdl-1.3.texi

** gnunet-c-tutorial.texi
 -> figs/Service.pdf
 -> figs/System.pdf
 -> tutorial-examples/*.c
 -> gpl-3.0.texi
 -> fdl-1.3.texi

- gnunet-c-tutorial-v1.pdf: original LaTeX "gnunet-c-tutorial.pdf".
- man folder: the man pages.
- doxygen folder
- outdated-and-old-installation-instructions.txt: self described within the file.


Use `gendocs', add to the manual/ directory of the web site.

  $ cd doc
  $ gendocs.sh gnunet "GNUnet 0.10.X Reference Manual"
