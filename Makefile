all: webgoat sbd_labor_1

webgoat:
	pandoc md/WebGoat.md -o pdf/WebGoat.pdf --template eisvogel.tex --from markdown --listings -V titlepage=true

sbd_labor_1:
	pandoc md/SBD_Labor_1.md -o pdf/SBD_Labor_1.pdf --template eisvogel.tex --from markdown --listings -V titlepage=true
