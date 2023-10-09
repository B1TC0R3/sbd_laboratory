all:
	pandoc SDB_Labor.md -o SDB_Labor.pdf --template eisvogel.tex --from markdown --listings -V titlepage=true
