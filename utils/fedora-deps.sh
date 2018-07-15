#!/bin/sh
git submodule update --init --recursive
dnf install procps-ng-devel gmp-devel boost-devel cmake gcc-c++ openssl-devel python3-devel

