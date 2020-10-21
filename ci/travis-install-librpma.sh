#!/bin/bash -e

# librpma v0.9.0 release
LIBRPMA_VERSION=0.9.0

# pmdk v1.9.1 release
PMDK_VERSION=1.9.1

WORKDIR=$(pwd)

#
# The '/bin/sh' shell used by PMDK's 'make install'
# does not know the exact localization of clang
# and fails with:
#    /bin/sh: 1: clang: not found
# if CC is not set to the full path of clang.
#
export CC=$(which $CC)

# Install PMDK libraries, because PMDK's libpmem is a dependency of librpma.
# Install it from a release package with already generated documentation,
# in order to not install 'pandoc'.
wget https://github.com/pmem/pmdk/releases/download/${PMDK_VERSION}/pmdk-${PMDK_VERSION}.tar.gz
tar -xzf pmdk-${PMDK_VERSION}.tar.gz
cd pmdk-${PMDK_VERSION}
make -j$(nproc) NDCTL_ENABLE=n
sudo make -j$(nproc) install prefix=/usr NDCTL_ENABLE=n
cd $WORKDIR
rm -rf pmdk-${PMDK_VERSION}

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
