OUT_DIR = ./bin
clean:
	rm -rf ${OUT_DIR}
	mkdir -p ${OUT_DIR}

run:
	cd ${OUT_DIR} && \
	([ -f out ] || zokrates compile -i ../main.zok) && \
	(([ -f proving.key ] && [ -f verification.key ]) || zokrates setup) && \
	([ -f witness ] || cat inputs.txt | zokrates compute-witness --stdin) && \
	([ -f proof.json ] || zokrates generate-proof) && \
	zokrates verify

sign:
	python sign.py
