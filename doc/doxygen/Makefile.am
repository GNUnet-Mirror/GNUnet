# This Makefile.am is in the public domain
all:
	@echo -e \
"Generate documentation:\n" \
"\tmake full - full documentation with dependency graphs (slow)\n" \
"\tmake fast - fast mode without dependency graphs"

full: gnunet.doxy
	doxygen $<

fast: gnunet.doxy
	sed 's/\(HAVE_DOT.*=\).*/\1 NO/' $< | doxygen -

clean:
	rm -rf html
