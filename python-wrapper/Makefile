.PHONY: build clean

build: pre_python.c setup.py ../pre/pre-afgh-relic.c
	python3 setup.py build_ext --inplace

clean:
	rm -rf pypre.*.so build/*
