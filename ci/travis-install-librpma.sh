#!/bin/bash -e

# librpma v0.9.0 release
LIBRPMA_VERSION=0.9.0

WORKDIR=$(pwd)

# install librpma
git clone https://github.com/pmem/rpma.git
mkdir -p rpma/build
cd rpma/build
git checkout -b v$LIBRPMA_VERSION $LIBRPMA_VERSION
cmake .. -DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_INSTALL_PREFIX=/usr \
	-DBUILD_DOC=OFF \
	-DBUILD_EXAMPLES=OFF \
	-DBUILD_TESTS=OFF
make -j$(nproc)
sudo make -j$(nproc) install
cd $WORKDIR
rm -rf rpma
