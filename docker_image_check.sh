#!/bin/bash
#set -x
#
# docker_image_checks - Security Checks of Docker Images
# Copyright (C) AJRepo

#Supported TAGS
#SUPPORTED_TAGS="https://gitlab.com/nvidia/container-images/cuda/blob/master/doc/supported-tags.md"

SECURITY_RISK_LEVEL=0
SECURITY_WARNINGS=()

LOCAL_VENDOR_ROOT_DIR="/srv/dockercheck/"

DRY_RUN='false'
DEBUG='false'
VERBOSE='false'

VENDOR_TGZ_DOWNLOAD_FILE="/tmp/latest_docker_image.tgz"

# Function: usage() print usage.
function usage() {
	echo "Usage: $(basename "$0") -p " 2>&1
	echo '   -d    Debug mode (print more)'
	echo '   -v    Verbose mode (print more)'
	echo '   -n    Dry Run (do not download)'
	echo '   -r    Root docker image to analyze (nvida, ubuntu)'
	exit 1
}

#Function print_v
function print_v() {
   local level=$1

   case $level in
      v) # Verbose
      [[ "$VERBOSE" == 'true' ]] && echo -e "[VER] ${*:2}"
      ;;
      d) # Debug
      [[ "$DEBUG" == 'true' ]] && echo -e "[DEB] ${*:2}"
      ;;
      e) # Error
      echo -e "[ERR] ${*:2}"
      ;;
      w) # Warning
      echo -e "[WAR] ${*:2}"
      ;;
      *) # Any other level
      echo -e "[INF] ${*:2}"
      ;;
   esac
}


#Function: print_final_report() Prints final security risk report
function print_final_report() {
	echo "DOCKER_IMAGE_HASH=$DOCKER_HASH"
	
	echo "Report for $DOCKER_IMAGE"
	echo "Original Source image = ${aIMAGE_SOURCE_URL[$DOCKER_IMAGE]}"
	echo "SECURITY RISK LEVEL = $SECURITY_RISK_LEVEL"
	echo "Security Warnings:"
	
	for SECURITY_WARNING in "${SECURITY_WARNINGS[@]}"
	do
		echo "* $SECURITY_WARNING"
	done
}

#Function: set_docker_param(): set the param based on docker root
# input: $1 return variable
# input: $2 associative array with valid parameters
# input: $3 the key parameter to look up in $2 variable
function set_docker_param() {
	local known_docker_param='false'
	local -n return_val=$1
	local -n aa_valid_params=$2
	local param_to_lookup=$3

	print_v d " PARAM_to_lookup=$param_to_lookup"
	#echo "FOO='" "${aa_valid_params[@]}" "'"
	#echo "BAR=" "${aa_valid_params[$param_to_lookup]}"

	if [[ $param_to_lookup == "" ]]; then
		echo "Docker param not set. Picking default"
		this_docker_core=$( echo "${!aa_valid_params[@]}" | awk '{print $0}')
		return_val=${aa_valid_params[$this_docker_core]}
		known_docker_param='true'
	else
		if [[ ${aa_valid_params[$param_to_lookup]} != "" ]]; then
			return_val=${aa_valid_params[$param_to_lookup]}
			known_docker_param='true'
		fi
	fi

	if [[ $known_docker_param == 'false' ]]; then
		print_v d " Unknown Docker Param. Returning '' "
		return_val=''
	else
		print_v d " Docker Param=$return_val"
	fi

	return 0
}

# Function: pass in root and optionally tag, product for analysis
# this_docker_core string: is required
function setup_docker_globals() {
    local optarg_docker_root=$1
    local this_docker_tag=$2
	local this_docker_product=''
    local this_docker_core=''

	declare -A aIMAGE_ROOT
	declare -A aIMAGE_TAG
	declare -A aIMAGE_PRODUCT

	aIMAGE_ROOT["ubuntu"]="ubuntu"
	aIMAGE_ROOT["ubuntu20"]="ubuntu"
	aIMAGE_ROOT["nvidia"]="nvidia"

	aIMAGE_TAG["ubuntu"]="focal"
	aIMAGE_TAG["ubuntu20"]="focal"
	aIMAGE_TAG["nvidia"]="11.0-base"

	aIMAGE_PRODUCT["ubuntu"]=""
	aIMAGE_PRODUCT["nvidia"]="cuda"

	print_v d " $this_docker_core with " "${aIMAGE_ROOT[@]}"

	#set variable this_docker_tag
	set_docker_param this_docker_core aIMAGE_ROOT "$optarg_docker_root"
	if [[ $this_docker_core == '' ]]; then
		echo "Error: No docker root set. Exiting 1"
		exit 1
	fi

	#print_v d " about to lookup aIMAGE_PRODUCT"
	#set variable this_docker_tag
	set_docker_param this_docker_tag aIMAGE_TAG "$this_docker_core"

	if [[ $this_docker_tag == 'false' ]]; then
		echo "Error: Docker tag not set. Used " "${aIMAGE_TAG[@]}" " Error: exiting"
		exit 1
	else
		print_v d " Docker Tag=$this_docker_tag"
	fi

	#set variable this_docker_product
	print_v d " about to lookup aIMAGE_PRODUCT"
	set_docker_param this_docker_product aIMAGE_PRODUCT "$this_docker_core"

	if [[ $this_docker_product == 'false' ]]; then
		echo "Error: Docker product not set. Used " "${aIMAGE_PRODUCT[@]}" " Error: exiting"
		exit 1
	else
		print_v d " Docker product=$this_docker_product"
	fi

	print_v v "THIS DOCKER ROOT = $this_docker_core"
	print_v v "THIS DOCKER TAG = $this_docker_tag"
	print_v v "THIS DOCKER PRODUCT = $this_docker_product"

	THIS_DOCKER_CORE="$this_docker_core"
	THIS_DOCKER_TAG="$this_docker_tag"
	THIS_DOCKER_PRODUCT="$this_docker_product"
	DOCKER_IMAGE="$this_docker_core:$this_docker_tag"
	print_v v "THIS DOCKER_IMAGE = $DOCKER_IMAGE"
}

#Function: docker_256sum_check() download and check hashes for docker image
#
# input: $1 Already downloaded file to check
# input: $2 Where to download the file with hashes (e.g. verification data)
# input: $3 the filename for where to save the hash file
# global: SECURITY_RISK_LEVEL
# global: SECURITY_WARNINGS
function docker_256sum_check() {
	local this_image_filename=$1
	local this_image_hash_url=$2
	local this_tmp_hashfile=$3
	if [[ $this_image_hash_url != "" ]]; then
		print_v d "Checking Image of $this_image_filename"
		if [[ $DRY_RUN == 'false' ]]; then
			wget -O "$this_tmp_hashfile" "$this_image_hash_url"
		else
			print_v v "Skipping new download of docker_iamge_hashes"
		fi
		if ! grep "$this_image_filename" "$this_tmp_hashfile" | awk '{print $1, "$VENDOR_TGZ_DOWNLOAD_FILE"}' | sha256sum --check --; then
			echo "Download of Vendor original source image failed hash check."
			echo "Failed hash check means also failed security audit. Exiting"
			exit 1
		fi
	else
		echo "Couldn't find vendor's source hash checks."
		SECURITY_RISK_LEVEL=$((SECURITY_RISK_LEVEL + 1))
		SECURITY_WARNINGS+=("Image not signed by vendor")
	fi
}

# Function: docker_creation_date: Find the date the image was created
# Input: Docker image
# Output: image_creation_date YYYYMMDDHHMMSS
function docker_creation_date() {
	local image=$1
	local -n image_creation_date=$2
	local rawdate=""

	rawdate=$(sudo docker inspect "$image" | grep Created | awk '{print $2}' | sed -e /,/s/// | sed -e /\"/s///g )
	
	if [[ $rawdate == "" ]]; then
		echo "Error: Blank date"
		exit 1
	fi

	image_creation_date=$(date -u -d "$rawdate" +%Y%m%d%H%M%S)
	if [[ $image_creation_date == "" ]]; then
		echo "Error: Blank image_creation_date"
		exit 1
	fi

}
	

# Function: Which_docker_core()
function which_docker_core_image() {
	#local core_url="https://partner-images.canonical.com/core/focal/"
	local core_url=$1
	local docker_date=$2
	local this_source_image_file=$3
	local -n this_docker_vendor_image=$4
	local greatest_date=""
	local local_hmsdate=""
	if [[ $1 = "" ]]; then
		"Error in getting core_url, exiting"
		exit 1
	fi
	
	for date_dir in $(wget --level=0 -O - "$core_url" | grep folder | sed /.*href=\"/s/// | sed /\\/.*/s///); do
		local_hmsdate="${date_dir}000000"
		if [ "$local_hmsdate" -le "$docker_date" ]; then
			greatest_date=$date_dir
		fi
	done

	if [[ $greatest_date != "" ]]; then
		this_docker_vendor_image="$core_url/$greatest_date/$this_source_image_file"
	else
		echo "Can't get core image. Exiting"
		exit 1
	fi

	if [[ $this_docker_vendor_image == "" ]]; then
		echo "Error: No vendor image"
		exit 1
	fi
}

#If called without args error out
if [[ ${#} -eq 0 ]]; then
	echo "Must be called with argument specifying client"
	usage
	exit 1
fi

DEBUG='false'
VERBOSE='false'
optstring="vndr:"
while getopts ${optstring} arg; do
	case ${arg} in
	n)
		DRY_RUN='true'
	;;
	d)
		DEBUG='true'
	;;
	v)
		VERBOSE='true'
	;;
	r)
		DOCKER_ROOT="${OPTARG}"
	;;
	esac
done

print_v d "BASH_SOURCE=${BASH_SOURCE[0]}"
print_v d "PWD=$PWD"

setup_docker_globals "$DOCKER_ROOT"

#which image to analyze


#Declare Associative Array Variables for various sources
declare -A aIMAGE_CORE_DIR
declare -A aIMAGE_TAG_DIR
declare -A aIMAGE_SOURCE_URL
declare -A aIMAGE_SOURCE_HASHES
declare -A aIMAGE_SOURCE_IMAGE_FILE
aIMAGE_SOURCE_IMAGE_FILE["ubuntu:focal"]="ubuntu-focal-core-cloudimg-amd64-root.tar.gz"
aIMAGE_SOURCE_IMAGE_FILE["nvidia:11.0-base"]="Dockerfile"

aIMAGE_SOURCE_HASHES["ubuntu:focal"]="https://partner-images.canonical.com/core/focal/current/SHA256SUMS"
#NVIDIA Doesn't have them
aIMAGE_SOURCE_HASHES["nvidia:11.0-base"]=""

# NVIDIA: See https://ngc.nvidia.com/catalog/containers/nvidia:cuda
# NVIDIA: Uses Ubuntu for their core image. So looking at NVIDIA requires looking
#         at the base Ubuntu packages and then NVIDIA deb packages.
aIMAGE_SOURCE_URL["ubuntu:focal"]="https://partner-images.canonical.com/core/focal/current/${aIMAGE_SOURCE_IMAGE_FILE['ubuntu:focal']}"
aIMAGE_SOURCE_URL["nvidia:11.0-base"]="https://gitlab.com/nvidia/container-images/cuda/blob/master/dist/11.2.2/ubuntu20.04-x86_64/runtime/cudnn8/Dockerfile"

# NVIDIA: See https://ngc.nvidia.com/catalog/containers/nvidia:cuda
# NVIDIA: Uses Ubuntu for their core image. So looking at NVIDIA requires looking
#         at the base Ubuntu packages and then NVIDIA deb packages.
#declare -A aIMAGE_SOURCE_DIR
#aIMAGE_SOURCE_DIR["ubuntu:focal"]="https://partner-images.canonical.com/core/focal/"
#aIMAGE_SOURCE_DIR["nvidia:11.0-base"]="https://gitlab.com/nvidia/container-images/cuda/blob/master/dist/11.2.2/ubuntu20.04-x86_64/runtime/cudnn8/"

aIMAGE_CORE_DIR["ubuntu"]="https://partner-images.canonical.com/core/"
aIMAGE_CORE_DIR["nvidia"]="https://gitlab.com/nvidia/container-images/cuda/blob/master/dist/11.2.2/ubuntu20.04-x86_64/runtime/"

aIMAGE_TAG_DIR["focal"]="focal/"
aIMAGE_TAG_DIR["11.0-base"]="cudnn8/"

this_source_url=""
print_v d " about to run aIMAGE_SOURCE_URL for $DOCKER_IMAGE, $THIS_DOCKER_TAG"
#set variable this_source_url (where we download the source docker image)
set_docker_param this_source_url aIMAGE_SOURCE_URL "$DOCKER_IMAGE"

print_v d "SOURCE URL= $this_source_url"


if [[ $THIS_DOCKER_PRODUCT != "" ]]; then
	IMAGE_VENDOR_PRODUCT="$THIS_DOCKER_CORE/$THIS_DOCKER_PRODUCT"
else
	IMAGE_VENDOR_PRODUCT="$THIS_DOCKER_CORE"
fi

#DOCKER_IMAGE set in setup_arrays
#DOCKER_IMAGE="$IMAGE_VENDOR_PRODUCT:${IMAGE_TAGS[$i]}"

print_v v "Checking $DOCKER_IMAGE"
print_v v "Source Image Identified as: ${aIMAGE_SOURCE_IMAGE_FILE[${DOCKER_IMAGE}]}"
print_v v "Source URL Identified as: ${aIMAGE_SOURCE_URL[${DOCKER_IMAGE}]}"

#######Download Vendor Source Image
if [[ ${aIMAGE_SOURCE_IMAGE_FILE[$DOCKER_IMAGE]} == "Dockerfile" ]]; then
	echo -n "This docker image doesn't use their own core image. "
	echo -n "E.g. Nvidia uses a DockerFile that references Ubuntu/UBI/CentOS cores. "
	echo "Getting DockerFile"
	DO_HASH_CHECK='false'
	DOCKERFILE_ONLY='true'
	if [[ $DRY_RUN == 'false' ]]; then
		wget -O /tmp/latest_docker_file.dockerfile ${aIMAGE_SOURCE_URL[$DOCKER_IMAGE]}
	else
		print_v v "Dry Run: Skipping download of ${aIMAGE_SOURCE_URL[$DOCKER_IMAGE]}"
	fi
elif [[ ${aIMAGE_SOURCE_URL[$DOCKER_IMAGE]} != "" ]]; then
	DOCKERFILE_ONLY='false'
	DO_HASH_CHECK='true'
	if [[ $DRY_RUN == 'false' ]]; then
		wget --directory-prefix="$LOCAL_VENDOR_ROOT_DIR" \
             --force-directories \
             -N  ${aIMAGE_SOURCE_URL[$DOCKER_IMAGE]}
	else
		print_v v "Dry Run: Skipping download of ${aIMAGE_SOURCE_URL[$DOCKER_IMAGE]}"
	fi

else
	echo "Couldn't find vendor's source image file. Exiting."
	exit 1
fi

if [[ $DO_HASH_CHECK == 'true' ]]; then
	#Download vendor hash file and check downloaded file image passes hash checks
	docker_256sum_check ${aIMAGE_SOURCE_IMAGE_FILE[$DOCKER_IMAGE]} ${aIMAGE_SOURCE_HASHES[$DOCKER_IMAGE]} /tmp/docker_image_hashes.txt
fi

#Download docker source image if it passes docker signing
print_v v "About to download docker image using 'sudo docker pull $DOCKER_IMAGE'"
if ! sudo DOCKER_CONTENT_TRUST=1 docker pull "$DOCKER_IMAGE"; then
	SECURITY_RISK_LEVEL=$((SECURITY_RISK_LEVEL + 1))
	SECURITY_WARNINGS+=("Image not signed by notary.docker.io")
	if ! sudo docker pull "$DOCKER_IMAGE"; then
		echo "Pulling $DOCKER_IMAGE failed: exiting"
		exit 1
	fi
fi


#CHECK HASH once arrived
print_v v "About to inspect image using 'sudo docker inspect $DOCKER_IMAGE'"
DOCKER_HASH=$(sudo docker inspect "$DOCKER_IMAGE" | grep "$IMAGE_VENDOR_PRODUCT@sha256")

if [[ $DOCKERFILE_ONLY == 'true' ]]; then
	echo "Dockerfile only. Can't do diff. Stopping and re-evaluate with core image"
	exit 0
fi

IMAGE_CREATION_DATE=""
docker_creation_date "$DOCKER_IMAGE" IMAGE_CREATION_DATE
print_v v "Docker Creation Date = $IMAGE_CREATION_DATE"

DOCKER_LOCAL_IMAGE_DIRECTORY="/srv/docker.$DOCKER_IMAGE.$IMAGE_CREATION_DATE"
if [ -d "$DOCKER_LOCAL_IMAGE_DIRECTORY" ]; then
	print_v v "Docker local image already saved"
else
	print_v v "Making Directory $DOCKER_LOCAL_IMAGE_DIRECTORY"
	mkdir "$DOCKER_LOCAL_IMAGE_DIRECTORY"
fi

THIS_DOCKER_VENDOR_IMAGE=""
which_docker_core_image "${aIMAGE_CORE_DIR[$THIS_DOCKER_CORE]}/${aIMAGE_TAG_DIR[$THIS_DOCKER_TAG]}" "$IMAGE_CREATION_DATE" "${aIMAGE_SOURCE_IMAGE_FILE[$DOCKER_IMAGE]}" THIS_DOCKER_VENDOR_IMAGE

print_v d "DOCKER_IMAGE=$DOCKER_IMAGE"
print_v d "THIS_DOCKER_TAG=$THIS_DOCKER_TAG"
print_v d "THIS_CORE_DIR=${aIMAGE_CORE_DIR[$THIS_DOCKER_CORE]}"
print_v d "THIS_TAG_DIR=${aIMAGE_TAG_DIR[$THIS_DOCKER_TAG]}"
print_v d "IMAGE_CREATION_DATE=$IMAGE_CREATION_DATE"
print_v d "THIS_DOCKER_VENDOR_IMAGE=$THIS_DOCKER_VENDOR_IMAGE"


# Extracting the layers and then extracting the layers all to one combined directory.
# Then analyze shared image to vendor core image
print_v v "About to do security comparison of ${aIMAGE_SOURCE_IMAGE_FILE[$DOCKER_IMAGE]} and $DOCKER_IMAGE"
# shellcheck disable=1091
source ./SCAP_docker.sh "$VENDOR_TGZ_DOWNLOAD_FILE" "$DOCKER_IMAGE"

print_final_report


# tabs instead of spaces in bash scripts for heredoc <<-
# vim: ts=4 noexpandtab
