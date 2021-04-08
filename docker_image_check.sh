#!/bin/bash
#set -x
#
# docker_image_checks - Security Checks of Docker Images
# Copyright (C) AJRepo

#Supported TAGS
#SUPPORTED_TAGS="https://gitlab.com/nvidia/container-images/cuda/blob/master/doc/supported-tags.md"

SECURITY_LEVEL=0
SECURITY_CODES=()

DRY_RUN='false'

function usage {
	echo "Usage: $(basename "$0") -p " 2>&1
	echo '   -n    Dry Run (do not download)'
	echo '   -d    Docker image to analize (nvida, ubuntu)'
	exit 1
}

#Function: set_docker_param(): set the param based on docker root
function set_docker_param {
	local known_docker_param='false'
	local -n return_val=$1
	local -n aa_valid_params=$2
	local param_to_lookup=$3

	echo "PARAM=$param_to_lookup"
	echo "FOO=" "${aa_valid_params[@]}"
	echo "BAR=" "${aa_valid_params[$param_to_lookup]}"

	if [[ $param_to_lookup == "" ]]; then
		echo "Docker param not set. Picking default"
		this_docker_root=$( echo "${!aa_valid_params[@]}" | awk '{print $0}')
		return_val=${aa_valid_params[$this_docker_root]}
		known_docker_param='true'
	else
		if [[ ${aa_valid_params[$param_to_lookup]} != "" ]]; then
			return_val=${aa_valid_params[$param_to_lookup]}
			known_docker_param='true'
		fi
	fi

	if [[ $known_docker_param == 'false' ]]; then
		echo "Unknown Docker Param. Exiting"
		return_val='false'
		exit 1
	else
		echo "Docker Param=$return_val"
	fi

	return 0
}

# Function: pass in root and optionally tag, product for analysis
# this_docker_root string: is required
function setup_arrays {
    local this_docker_root=$1
    local this_docker_tag=$2
	local this_docker_product=''

    local known_docker_root='false'

	declare -A aIMAGE_TAG
	declare -A aIMAGE_PRODUCT

	aIMAGE_TAG["ubuntu"]="focal"
	aIMAGE_TAG["nvidia"]="11.0-base"

	aIMAGE_PRODUCT["ubuntu"]=""
	aIMAGE_PRODUCT["nvidia"]="cuda"

	echo "DEBUG: $this_docker_root"

	IMAGE_VENDORS=("nvidia" "ubuntu")
	if [[ $this_docker_root == "" ]]; then
		echo "Docker root not set. Defaulting to ubuntu"
		this_docker_root="ubuntu"
		known_docker_root='true'
	else
		for this_root in "${IMAGE_VENDORS[@]}"; do
			if [[ $this_root == "$this_docker_root" ]]; then
				known_docker_root='true'
			fi
		done
	fi

	if [[ $known_docker_root == 'false' ]]; then
		echo "Unknown Docker Root. Exiting"
		exit 1
	else
		echo "Docker Root=$this_docker_root"
	fi

	set_docker_param this_docker_tag aIMAGE_TAG "$this_docker_root"

	if [[ $this_docker_tag == 'false' ]]; then
		echo "Docker tag not set. Used " "${aIMAGE_TAG[@]}" " Error: exiting"
		exit 1
	else
		echo "Docker Tag=$this_docker_tag"
	fi

	set_docker_param this_docker_product aIMAGE_PRODUCT "$this_docker_root"

	if [[ $this_docker_product == 'false' ]]; then
		echo "Docker product not set. Used " "${aIMAGE_PRODUCT[@]}" " Error: exiting"
		exit 1
	else
		echo "Docker product=$this_docker_product"
	fi

	echo "THIS TAG = $this_docker_tag"
	echo "THIS PRODUCT = $this_docker_product"

	DOCKER_IMAGE="$this_docker_product:$this_docker_tag"
}

#If called without args error out
if [[ ${#} -eq 0 ]]; then
	echo "Must be called with argument specifying client"
	usage
	exit 1
fi

optstring="nd:"
while getopts ${optstring} arg; do
	case ${arg} in
	n)
		DRY_RUN='true'
	;;
	d)
		DOCKER_ROOT="${OPTARG}"

	;;
	esac
done

echo "DOCKER_ROOT=$DOCKER_ROOT"

setup_arrays "$DOCKER_ROOT"

exit 0


#which image to analize
i=1

IMAGE_PRODUCTS=("cuda" "")
#Declare Associative Array Variables for various sources
declare -A aIMAGE_SOURCE_URL
declare -A aIMAGE_SOURCE_HASHES
declare -A aIMAGE_SOURCE_IMAGE
aIMAGE_SOURCE_IMAGE["ubuntu:focal"]="ubuntu-focal-core-cloudimg-amd64-root.tar.gz"
aIMAGE_SOURCE_HASHES["ubuntu:focal"]="https://partner-images.canonical.com/core/focal/current/SHA256SUMS"
aIMAGE_SOURCE_URL["ubuntu:focal"]="https://partner-images.canonical.com/core/focal/current/${aIMAGE_SOURCE_IMAGE['ubuntu:focal']}"




if [[ ${IMAGE_PRODUCTS[$i]} != "" ]]; then
	IMAGE_VENDOR_PRODUCT="${IMAGE_VENDORS[$i]}/${IMAGE_PRODUCTS[$i]}"
else
	IMAGE_VENDOR_PRODUCT="${IMAGE_VENDORS[$i]}"
fi

#DOCKER_IMAGE set in setup_arrays
#DOCKER_IMAGE="$IMAGE_VENDOR_PRODUCT:${IMAGE_TAGS[$i]}"

echo "Checking $DOCKER_IMAGE"
echo "Source Image Identified as: ${aIMAGE_SOURCE_IMAGE[${DOCKER_IMAGE}]}"

if [[ ${aIMAGE_SOURCE_URL[$DOCKER_IMAGE]} != "" ]]; then
	if [[ $DRY_RUN == 'false' ]]; then
		wget -O /tmp/latest_docker_image.tgz ${aIMAGE_SOURCE_URL[$DOCKER_IMAGE]}
	fi
else
	echo "Couldn't find vendor's source image. Exiting."
	exit 1
fi

if [[ ${aIMAGE_SOURCE_HASHES[$DOCKER_IMAGE]} != "" ]]; then
	echo "DEBUG 1: Uncomment to activate ${aIMAGE_SOURCE_IMAGE[$DOCKER_IMAGE]}"
	#wget -O /tmp/image_hashes.txt ${aIMAGE_SOURCE_HASHES[$DOCKER_IMAGE]}
	if ! grep ${aIMAGE_SOURCE_IMAGE[$DOCKER_IMAGE]} /tmp/image_hashes.txt | awk '{print $1, "/tmp/latest_docker_image.tgz"}' | sha256sum --check --; then
		echo "Download of Vendor original source image failed hash check. Exiting"
		exit 1
	fi
else
	echo "Couldn't find vendor's source hash checks."
	SECURITY_LEVEL=$((SECURITY_LEVEL + 1))
	SECURITY_CODES+=("Image not signed by vendor")
fi

exit

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

# tabs instead of spaces in bash scripts for heredoc <<-
# vim: ts=4 noexpandtab
