#!/bin/bash
# This script expects to be invoked from the base fio directory.
set -eu

SCRIPT_DIR=$(dirname "$0")
# shellcheck disable=SC1091
. "${SCRIPT_DIR}/common.sh"

install_ubuntu() {
    local pkgs

    cat <<DPKGCFG | sudo tee /etc/dpkg/dpkg.cfg.d/dpkg-speedup > /dev/null
# Skip fsync
force-unsafe-io
# Don't install documentation
path-exclude=/usr/share/man/*
path-exclude=/usr/share/locale/*/LC_MESSAGES/*.mo
path-exclude=/usr/share/doc/*
DPKGCFG
    # Packages available on i686 and x86_64
    pkgs=(
        libcunit1-dev
        libcurl4-openssl-dev
        libibverbs-dev
        libnuma-dev
        librdmacm-dev
        valgrind
    )
    if [ "${CI_EVENT}" == "schedule" ]; then
	pkgs+=(
            libaio-dev
            libfl-dev
        )
    fi
    case "${CI_TARGET_ARCH}" in
        "i686")
            sudo dpkg --add-architecture i386
            pkgs=("${pkgs[@]/%/:i386}")
            pkgs+=(
                gcc-multilib
                pkg-config:i386
            )
            ;;
        "x86_64")
            pkgs+=(
                libgoogle-perftools-dev
                libnbd-dev
                libpmem-dev
                libpmemblk-dev
                libtcmalloc-minimal4
            )
            if [ "${CI_EVENT}" == "schedule" ]; then
                pkgs+=(
                    libglusterfs-dev
                    libiscsi-dev
                    librbd-dev
                    nvidia-cuda-dev
		)
	    fi
            ;;
    esac

    # Architecture-independent packages and packages for which we don't
    # care about the architecture.
    pkgs+=(
        python3-scipy
    )

    echo "Updating APT..."
    sudo apt-get -qq update
    echo "Installing packages..."
    sudo apt-get install --no-install-recommends -qq -y "${pkgs[@]}"
}

install_linux() {
    install_ubuntu
}

install_macos() {
    # Assumes homebrew and python3 are already installed
    #echo "Updating homebrew..."
    #brew update >/dev/null 2>&1
    echo "Installing packages..."
    HOMEBREW_NO_AUTO_UPDATE=1 brew install cunit
    pip3 install scipy six
}

main() {
    set_ci_target_os

    install_function="install_${CI_TARGET_OS}"
    ${install_function}

    echo "Python3 path: $(type -p python3 2>&1)"
    echo "Python3 version: $(python3 -V 2>&1)"
}

main
