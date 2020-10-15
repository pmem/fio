#!/bin/bash
set -eu

CI_TARGET_ARCH="${BUILD_ARCH:-$TRAVIS_CPU_ARCH}"
case "$TRAVIS_OS_NAME" in
    "linux")
	# Architecture-dependent packages.
	pkgs=(
	    libcunit1-dev
	    libgoogle-perftools-dev
	    libibverbs-dev
	    libnuma-dev
	    librdmacm-dev
	)
	if [[ "$TRAVIS_EVENT_TYPE" == "cron" ]]; then
		pkgs+=(
		    libaio-dev
		    libfl-dev
		    libiscsi-dev
		    librbd-dev
		    libz-dev
	        )
	fi
	case "$CI_TARGET_ARCH" in
	    "x86")
		pkgs=("${pkgs[@]/%/:i386}")
		pkgs+=(
		    gcc-multilib
		    pkg-config:i386
	        )
		;;
	    "amd64")
		[ "$TRAVIS_EVENT_TYPE" == "cron" ] && pkgs+=(nvidia-cuda-dev)
		;;
	esac
	if [[ "$TRAVIS_EVENT_TYPE" == "cron" ]] && [[ $CI_TARGET_ARCH != "x86" ]]; then
		pkgs+=(glusterfs-common)
	fi
	# Architecture-independent packages and packages for which we don't
	# care about the architecture.
	pkgs+=(
	    bison
	    flex
	    python3
	    python3-scipy
	    python3-six
	)
	sudo apt-get -qq update
	sudo apt-get install --no-install-recommends -qq -y "${pkgs[@]}"
	# librpma is supported on the amd64 (x86_64) architecture for now
	if [[ $CI_TARGET_ARCH == "amd64" ]]; then
		# install librpma from sources from GitHub
		ci/travis-install-librpma.sh
	fi
	;;
    "osx")
	brew update >/dev/null 2>&1
	brew install cunit
	pip3 install scipy six
	;;
esac

echo "Python3 path: $(type -p python3 2>&1)"
echo "Python3 version: $(python3 -V 2>&1)"
