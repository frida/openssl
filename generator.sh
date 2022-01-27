#!/bin/bash
set -e

cd "$(dirname "${BASH_SOURCE[0]}")"

# Node.js version should bundle OpenSSL of matching version to one specified in wrap file
node_version=cde3296f5f6c7054c0bcb1dd9e1ee8a43ec3b3f1
openssl_version="$OPENSSL_VERSION"

if [ -z "$openssl_version" ]; then
  openssl_version="3.0.12+quic"
fi

rm -rf node
git clone https://github.com/nodejs/node.git
cd node
git checkout $node_version
cd ..

rm -rf generated-config

pushd node/deps/openssl

# Apply patch that will allow us generate `meson.build` for different targets
patch -p3 -i ../../../generator-patches/node.patch
# Copy `meson.build` template file
cp ../../../meson.build.tmpl config/

# Swap bundled OpenSSL in Node.js with upstream
rm -rf openssl
git clone --depth 1 --branch "openssl-$openssl_version" https://github.com/quictls/openssl.git
pushd openssl
for topic in darwin qnx; do
  patch -p1 -i ../../../../generator-patches/openssl-$topic.patch
done
popd

rm -rf config/archs
LANG=C make -C config

# Copy generated files back into correct place
cmd='mkdir -p ../../../generated-$(dirname "$1"); cp "$1" ../../../generated-"$1"'
find config/archs -name 'meson.build' -exec sh -c "$cmd" _ignored {} \;
find config/archs -name '*.asm' -exec sh -c "$cmd" _ignored {} \;
find config/archs -name '*.c' -exec sh -c "$cmd" _ignored {} \;
find config/archs -name '*.h' -exec sh -c "$cmd" _ignored {} \;
find config/archs -iname '*.s' -exec sh -c "$cmd" _ignored {} \;

# AIX is not supported by Meson
rm -rf ../../../generated-config/archs/aix*
# 32-bit s390x not supported in Meson
rm -rf ../../../generated-config/archs/linux32-s390x
# This is for old gas/nasm versions, we do not care about them
rm -rf ../../../generated-config/archs/*/asm_avx2
# Remove build info files, we use hardcoded deterministic one instead
rm -rf ../../../generated-config/archs/*/*/crypto/buildinf.h

popd

rm -rf node
