#!/bin/bash
# This script expects to be invoked from the base fio directory.
set -eu

main() {
    echo "Running long running tests..."
    echo "CI_EVENT=${CI_EVENT}"
    export PYTHONUNBUFFERED="TRUE"
    if [[ "${CI_TARGET_ARCH}" == "arm64" ]]; then
        sudo python3 t/run-fio-tests.py --skip 6 1007 1008 --debug -p 1010:"--skip 15 16 17 18 19 20"
    elif [[ "${CI_EVENT}" == "schedule" ]]; then
        sudo python3 t/run-fio-tests.py --skip 6 1007 1008 --debug
    else
        sudo python3 t/run-fio-tests.py --skip 2 6 1000 1001 1002 1003 1004 1005 1006 1007 1008 1009 1010 1011 --debug
    fi
}

main
