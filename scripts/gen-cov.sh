#!/bin/sh

cd "`dirname "${0}"`"

mkdir -p _cov
gcovr -f '.*plusaes.hpp' -r ../mac --html --html-details -o _cov/coverage.html
