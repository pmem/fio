#!/bin/bash -e

# 01.02.2021 Merge pull request #802 from osalyk/rejected
LIBRPMA_VERSION=f5ccce39674f6837d788da24b5646329affb8757

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
