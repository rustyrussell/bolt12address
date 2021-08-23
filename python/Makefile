#! /usr/bin/make

BOLTDIR=../../lightning-rfc
BOLT12DIR= ../../bolt12

generated.py: addressproof.csv preamble.py
	DIR=`pwd`; cd $(BOLT12DIR)/tools && ./generate-code.py --language=py --preamble=$$DIR/preamble.py --spec=$$DIR/$< addressproof > $$DIR/$@

addressproof.csv: ../README.md
	$(BOLTDIR)/tools/extract-formats.py $< > $@

