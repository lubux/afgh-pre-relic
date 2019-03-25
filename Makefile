.PHONY: all test test-python benchmark python install install-python clean

all: lib/libpre-afgh-relic.so

test:
	./bin/test_pre

test-python:
	cd python-wrapper && python3 test.py

benchmark:
	./bin/benchmark_pre

install: lib/libpre-afgh-relic.so
	cp pre/pre-afgh-relic.h /usr/local/include
	cp lib/* /usr/local/lib

install-python: python
	cp python-wrapper/pypre.*.so lib/

python:
	make -C python-wrapper

lib/libpre-afgh-relic.so: pre/CMakeLists.txt $(ls pre/*.{c,h,cpp})
	cd pre && cmake . && make

clean:
	rm -f lib/* bin/*
	make -C python-wrapper clean
	make -C pre clean
	rm -rf pre/Makefile pre/CMakeCache.txt pre/CMakeFiles pre/cmake_install.cmake
