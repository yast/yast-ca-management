#! /bin/bash

# TODO: This is a modified copy of the
# https://github.com/yast/docker-yast-ruby/blob/master/yast-travis-ruby
# file which runs the tests builds the package as the "nobody" user.
# 
# The problem is that the tests are silently skipped for non-root users
# and for root they fail. (They are probably broken for long time
# but very likely nobody noticed that...)

###########################################################################

# This is a CI build script for running inside the Travis builds.
# It's designed for the YaST packages written in Ruby.

# exit on error immediately, print the executed commands
set -e -x

rake check:pot

if [ -e .rubocop.yml ]; then
  rubocop
else
  # if rubocop is not used then at least check the syntax
  rake check:syntax
fi;

if [ -e .spell.yml ]; then
  rake check:spelling
fi

yardoc

chown -R nobody:nobody /usr/src/app

# autotools based package
if [ -e Makefile.cvs ]; then
  make -f Makefile.cvs
  make -s
  make -s install
  su nobody -c "make -s check VERBOSE=1 Y2DIR=`pwd`"
fi

# enable coverage reports
COVERAGE=1 CI=1 rake test:unit

# build the binary package locally, use plain "rpmbuild" to make it simple
rake tarball > /dev/null 2>&1

PKG_DIR=~nobody/rpmbuild

mkdir -p $PKG_DIR/SOURCES/
cp package/* $PKG_DIR/SOURCES/
chown -R nobody:nobody $PKG_DIR

# Build the binary package, skip the %check section,
# the tests have been already executed outside RPM build.
su nobody -c "rpmbuild -bb --nocheck package/*.spec"

# test the %pre/%post scripts by installing/updating/removing the built packages
# ignore the dependencies to make the test easier, as a smoke test it's good enough
rpm -iv --force --nodeps $PKG_DIR/RPMS/*/*.rpm
rpm -Uv --force --nodeps $PKG_DIR/RPMS/*/*.rpm
# get the plain package names and remove all packages at once
rpm -ev --nodeps `rpm -q --qf '%{NAME} ' -p $PKG_DIR/RPMS/*/*.rpm`
