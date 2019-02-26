.PHONY: all python install clean

all: python

python: install
	make -C python-wrapper
	cp python-wrapper/pypre.*.so lib/

install: lib/libpre-afgh-relic.so
	cp pre/pre-afgh-relic.h /usr/local/include
	cp lib/* /usr/local/lib

lib/libpre-afgh-relic.so: pre/CMakeLists.txt $(ls pre/*.{c,h,cpp})
	cd pre && cmake . && make

clean:
	rm -f lib/* bin/*
	make -C python-wrapper clean
	-make -C pre clean
	rm -rf pre/Makefile pre/CMakeCache.txt pre/CMakeFiles pre/cmake_install.cmake
