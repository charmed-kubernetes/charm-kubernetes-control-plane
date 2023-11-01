#!/bin/bash
set -euo pipefail

# When changing CNI_VERSION, it should be updated in both
# charm-kubernetes-control-plane/build-cni-resources.sh and
# charm-kubernetes-worker/build-cni-resources.sh
CNI_VERSION="v1.2.0"

# Check for required commands
for cmd in wget sha256sum; do
	if ! command -v $cmd &>/dev/null; then
		echo "Error: $cmd is not installed." >&2
		exit 1
	fi
done

fetch() {
	local url="$1"
	local filename="${url##*/}"

	wget -O "$filename" "$url" || {
		echo "Failed to download $url"
		exit 1
	}
	echo "$filename"
}

fetch_and_validate() {
	local binary_url="$1"
	local sha_url="$2"
	local arch="$3"

	local binary_file=$(fetch "$binary_url")
	local sha_file=$(fetch "$sha_url")

	sha256sum -c "$sha_file" || {
		echo "Checksum validation failed for $binary_file"
		exit 1
	}
	mv "$binary_file" "cni-plugins-${arch}.tar.gz"
	rm "$sha_file"
}

ARCH=${ARCH:-"amd64 arm64 s390x"}
for arch in $ARCH; do
	fetch_and_validate \
		"https://github.com/containernetworking/plugins/releases/download/${CNI_VERSION}/cni-plugins-linux-${arch}-${CNI_VERSION}.tgz" \
		"https://github.com/containernetworking/plugins/releases/download/${CNI_VERSION}/cni-plugins-linux-${arch}-${CNI_VERSION}.tgz.sha256" \
		"$arch"
done
