webgoat  = WebGoat
sbdlab1  = SBD_Labor_1
sbdlab2  = SBD_Labor_2
mddir    = md
pdfdir   = pdf
template = eisvogel.tex
titlepagetextcolor   = ffffff
titlepagebackground  = .img/titlepage_background_dark_logo.png

format = --template $(template) --from markdown --listings -V titlepage=true -V titlepage-background=$(titlepagebackground) -V titlepage-text-color=$(titlepagetextcolor) -V titlepage-color=323232 -V toc-own-page=true

all: webgoat sbd_labor_2

webgoat:
	pandoc $(mddir)/$(webgoat).md -o $(pdfdir)/$(webgoat).pdf $(format)

sbd_labor_1:
	pandoc $(mddir)/$(sbdlab1).md -o $(pdfdir)/$(sbdlab1).pdf $(format)

sbd_labor_2:
	pandoc $(mddir)/$(sbdlab2).md -o $(pdfdir)/$(sbdlab2).pdf $(format)

