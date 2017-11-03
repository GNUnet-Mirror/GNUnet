To be moved to an appropriate section of "how to write documentation" or
"how to contribute to the documentation":

1. When writing documentation, please use gender-neutral wording when
   referring to people, such as singular “they”, “their”, “them”, and
   so forth. -> https://en.wikipedia.org/wiki/Singular_they

2. Keep line length below 74 characters.
   - Expection by texi2pdf output so far: URLs will break
     (inserted whitespace) when they contain linebreaks
     within the @url{} / @uref{}.

3. Do not use tab characters (see chapter 2.1 texinfo manual)

4. Use neutral language and third person perspective in the text

5. Use 2 spaces between sentences, so instead of:

     We do this and the other thing. This is done by foo.

   Write:

     We do this and the other thing.  This is done by foo.

6. Use @footnote{} instead of putting an @*ref{} to the footnote on a
   collected footnote-page.
   In a 200+ pages handbook it's better to have footnotes accessible
   without having to skip over to the end.

6.1 Avoid unnecessary footnotes, keep the text self-explanatory and
    in a simple language where possible/necessary.

* Completion Levels:

** chapters/philosophy: around 100% fixed after initial export.

* What's left to do

- Which Texlive modules are needed? Decrease the size.
- Update the content of gnunet documentation.

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
