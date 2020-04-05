#!/bin/bash

cd "`dirname "${0}"`"
cd ../

make distclean
./bootstrap
./configure
make

