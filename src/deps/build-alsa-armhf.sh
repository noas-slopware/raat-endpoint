#!/bin/sh
# Cross-build a minimal static alsa-lib for armhf (pcm + ctl, hw plugin only).
# usage: build-alsa-armhf.sh <toolchain-bin-dir> <out-prefix> [tarball-dir]
# The tarball is fetched from alsa-project.org unless already present in tarball-dir,
# and checked against the pinned sha256 below.
set -eu

ALSA_VER=1.2.16.1
ALSA_SHA256=f740db7f488255944ffd4428416ee3390a96742856916433df468c281436480e
ALSA_URL=https://www.alsa-project.org/files/pub/lib/alsa-lib-$ALSA_VER.tar.bz2

TCBIN=$1
PREFIX=$2
DL=${3:-$PREFIX/dl}

mkdir -p "$DL" "$PREFIX"
TARBALL=$DL/alsa-lib-$ALSA_VER.tar.bz2
if [ ! -f "$TARBALL" ]; then
	curl -sSfL -o "$TARBALL.part" "$ALSA_URL"
	mv "$TARBALL.part" "$TARBALL"
fi
echo "$ALSA_SHA256  $TARBALL" | sha256sum -c -

WORK=$PREFIX/build-alsa
rm -rf "$WORK"
mkdir -p "$WORK"
tar xjf "$TARBALL" -C "$WORK"
cd "$WORK/alsa-lib-$ALSA_VER"

PATH=$TCBIN:$PATH
export PATH
./configure --host=arm-linux-gnueabihf --prefix="$PREFIX" \
	--enable-static --disable-shared \
	--disable-python --disable-ucm --disable-topology --disable-alisp \
	--disable-seq --disable-rawmidi --disable-hwdep --disable-mixer \
	--disable-aload --disable-old-symbols --without-debug \
	--with-libdl=no --with-pcm-plugins=hw --with-ctl-plugins=hw \
	CFLAGS="-O2 -march=armv7-a -mfpu=neon -mfloat-abi=hard" >configure.log 2>&1 \
	|| { tail -40 configure.log; exit 1; }
make -j"$(nproc)" >make.log 2>&1 || { tail -40 make.log; exit 1; }
make install >install.log 2>&1 || { tail -40 install.log; exit 1; }
echo "alsa-lib $ALSA_VER installed in $PREFIX"
