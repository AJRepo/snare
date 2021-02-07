#!/bin/bash
#
# docker_image_checks - Security Checks of Docker Images
# Copyright (C) AJRepo

#Supported TAGS
#SUPPORTED_TAGS="https://gitlab.com/nvidia/container-images/cuda/blob/master/doc/supported-tags.md"

SECURITY_LEVEL=0
SECURITY_CODES=()

IMAGE_VENDORS=("nvidia" "ubuntu")
IMAGE_TAGS=("11.0-base" "focal")
IMAGE_PRODUCTS=("cuda" "")

if [[ ${IMAGE_PRODUCTS[0]} != "" ]]; then
	IMAGE_VENDOR_PRODUCT="${IMAGE_VENDORS[0]}/${IMAGE_PRODUCTS[0]}"
else
	IMAGE_VENDOR_PRODUCT="${IMAGE_VENDORS[0]}"
fi

DOCKER_IMAGE="$IMAGE_VENDOR_PRODUCT:${IMAGE_TAGS[0]}"

echo "Checking $DOCKER_IMAGE"

#Get image to analize
if ! sudo DOCKER_CONTENT_TRUST=1 docker pull "$DOCKER_IMAGE"; then
	SECURITY_LEVEL=$((SECURITY_LEVEL + 1))
	SECURITY_CODES+=("Image not signed by notary.docker.io")
	if ! sudo docker pull "$DOCKER_IMAGE"; then
		echo "Pulling $DOCKER_IMAGE failed: exiting"
		exit 1
	fi
fi

#CHECK HASH once arrived
DOCKER_HASH=$(sudo docker inspect "$DOCKER_IMAGE" | grep "$IMAGE_VENDOR_PRODUCT@sha256")

echo "DOCKER_IMAGE_HASH=$DOCKER_HASH"

echo "Report for $DOCKER_IMAGE"
echo "SECURITY LEVEL = $SECURITY_LEVEL"
echo "Errors:"

for SECURITY_CODE in "${SECURITY_CODES[@]}"
do
	echo "* $SECURITY_CODE"
done

# tabs instead of spaces in bash scripts for <<-
# vim: ts=4 noexpandtab
