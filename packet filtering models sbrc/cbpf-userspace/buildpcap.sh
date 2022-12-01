#!/usr/bin/env sh

rm -rf libpcap/build

cd libpcap
mkdir build
cd build
cmake ..
make

cd ../..
