webgoat  = WebGoat
sbdlab1  = SBD_Labor_1
sbdlab2  = SBD_Labor_2
mddir    = md
pdfdir   = pdf
template = eisvogel.tex
titlepagebackground  =./.img/titlepage_background.png

all: webgoat sbd_labor_2

webgoat:
	pandoc $(mddir)/$(webgoat).md -o $(pdfdir)/$(webgoat).pdf --template $(template) --from markdown --listings -V titlepage=true -V titlepage-background=$(titlepagebackground)

sbd_labor_1:
	pandoc $(mddir)/$(sbdlab1).md -o $(pdfdir)/$(sbdlab1).pdf --template $(template) --from markdown --listings -V titlepage=true -V titlepage-background=$(titlepagebackground)

sbd_labor_2:
	pandoc $(mddir)/$(sbdlab2).md -o $(pdfdir)/$(sbdlab2).pdf --template $(template) --from markdown --listings -V titlepage=true -V titlepage-background=$(titlepagebackground)

