To be moved to an appropriate section of "how to write documentation" or
"how to contribute to the documentation":

1. When writing documentation, please use gender-neutral wording when
   referring to people, such as singular “they”, “their”, “them”, and
   so forth. -> https://en.wikipedia.org/wiki/Singular_they

2. Keep line length below 74 characters.

* What's left to do

- Which Texlive modules are needed? Decrease the size.
- Update the content of gnunet documentation.

* How to use (hack) on this

** with guix

export the environment variable GUIX_PACKAGE_PATH as $GUIX_PACKAGE_PATH:gnunet/contrib/packages/guix/packages
guix environment gnunet-doc

** without guix

You need to have Texinfo and Texlive in your path.
sh bootstrap
./configure --enable-documentation
cd doc
make doc-all-give-me-the-noise

* structure (relations)

** gnunet.texi
 -> chapters/developer.texi
 -> chapters/installation.texi
 -> chapters/philosophy.texi
 -> chapters/user.texi
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
