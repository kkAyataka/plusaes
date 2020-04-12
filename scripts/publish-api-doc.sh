#!/bin/sh

cd "`dirname "${0}"`"
cd ../

readonly GIT_REPO=`git remote get-url origin`
readonly DOC_VER=`grep "version =" ../doc/conf.py | cut -d "'" -f 2`
readonly WORK_DIR="scripts/_gh-pages"
readonly DST_DIR="${WORK_DIR}/doc"

# print var
echo GIT_REPO=${GIT_REPO}
echo DOC_VER=${DOC_VER}
echo WORK_DIR=${WORK_DIR}
echo DST_VER_DIR=${DST_VER_DIR}

# clean
rm -rf build/html

# build API document
doxygen Doxyfile

# checkout gh-pages branch
if [ -d "${WORK_DIR}" ]; then
  cd "${WORK_DIR}"
  git pull
  cd -
else
  git clone --depth 1 -b gh-pages ${GIT_REPO} "${WORK_DIR}"
fi

# rm current files
rm -rf "${DST_DIR}/"

# cp html
cp -r build/html "${DST_DIR}"

# setup
touch "${WORK_DIR}/.nojekyll"

# ready to deploy to gh-pages
cd "${WORK_DIR}"
git add .
git status
