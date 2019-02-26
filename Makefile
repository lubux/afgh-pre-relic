.PHONY: all clean

all: lib/libpre-afgh-relic.so

lib/libpre-afgh-relic.so: pre/CMakeLists.txt $(ls pre/*.{c,h,cpp})
	cd pre && cmake . && make

clean:
	rm -f lib/* bin/*
