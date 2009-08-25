# HPCFS FUSE module
# 08/2009 - Dailymotion/PYKE

CC=gcc
CFLAGS=-Wall -O3 -s -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26
LDFLAGS=-lfuse -lpcre -lpthread

hpcfs: hpcfs.c
	$(CC) $(CFLAGS) -o hpcfs hpcfs.c $(LDFLAGS)

test: hpcfs
	./hpcfs ./root -o hpcfsconfig=debian/hpcfs.conf.sample -o intr -o debug

clean:

distclean:
	@rm -f hpcfs

deb: hpcfs
	@debuild -i -us -uc -b

deb-src:
	@debuild -i -us -uc -S

debclean:
	@debuild clean
