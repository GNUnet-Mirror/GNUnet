FILENAME = card
OPTIONS = --shell-escape

all:
	pdflatex $(OPTIONS) $(FILENAME).tex
	pdflatex $(OPTIONS) $(FILENAME).tex

clean:
	rm -fv $(FILENAME).dvi
	rm -fv $(FILENAME).ps
	rm -fv *.aux
	rm -fv $(FILENAME).log
	rm -fv $(FILENAME).toc
	rm -fv $(FILENAME).bbl
	rm -fv $(FILENAME).blg
