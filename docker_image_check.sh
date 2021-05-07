#!/bin/bash
#set -x
#
# docker_image_checks - Security Checks of Docker Images
# Copyright (C) AJRepo

#Supported TAGS
# Not all Docker Images support this. So can't use.  
#SUPPORTED_TAGS="https://registry.hub.docker.com/v1/repositories/$IMAGE/tags
#                https://hub.docker.com/r/nvidia/cuda/tags?page=1&ordering=last_updated
# Nvidia: 11.2.2-cudnn8-runtime-ubuntu20.04, 11.2.2-cudnn8-runtime-ubuntu20.04

SECURITY_RISK_LEVEL=0
SECURITY_WARNINGS=()

LOCAL_VENDOR_ROOT_DIR="/srv/dockercheck/"

DRY_RUN='false'
DEBUG='false'
VERBOSE='false'


#################################################################
#Begin Functions
#################################################################
# Function: print_usage() print usage.
function print_usage() {
	echo "Usage: $(basename "$0")  " 2>&1
	echo '   -c <0|1>    DOCKER_CONTENT_TRUST= (defaults to 1)'
	echo '   -d          Debug mode (print more)'
	echo '   -h          Help'
	echo '   -v          Verbose mode (print more)'
	echo '   -n          Dry Run (do not download)'
	echo '   -r <name>   Root docker image to analyze (nvida, ubuntu)'
	echo '   -t <name>   Docker tag to analyze (e.g. focal)'
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
# input: global $DOCKER_HASH
# input: global $DOCKER_IMAGE
# input: global $SECURITY_RISK_LEVEL
# input: global $SECURITY_WARNINGS[]
function print_final_report() {
	
	echo "Report for $DOCKER_IMAGE"
	echo "   DOCKER_IMAGE_HASH=$DOCKER_HASH"
	#echo "Original Source image = ${aIMAGE_SOURCE_URL[$DOCKER_IMAGE]}"
	echo "   SECURITY RISK LEVEL = $SECURITY_RISK_LEVEL"
	echo "   Security Warnings:"
	
	for SECURITY_WARNING in "${SECURITY_WARNINGS[@]}"
	do
		echo "      * $SECURITY_WARNING"
	done
}

# Function extract_docker_image() Extracts and unwinds the docker tar images
# Creates a tmp file and deletes it in /tmp/docker_save_tmp.tar
# input: $this_docker_image=$1 string   the image:tag of the docker image to extract
# input: $this_tar_dir=$2      string   the path to where to put the extraction
function extract_docker_image() {
	local this_docker_image="$1"
	local this_tar_dir="$2"
	if declare -F print_v > /dev/null; then
		print_v d "sudo docker save $this_docker_image"
	else
		echo "Verbose: sudo docker save $this_docker_image"
	fi
	#shellcheck disable=SC2024
	print_v d "about to sudo docker save $this_docker_image > /tmp/docker_save_tmp.tar"
	sudo docker save "$this_docker_image" -o /tmp/docker_save_tmp.tar

	if ! tar --directory="$this_tar_dir" -xf /tmp/docker_save_tmp.tar; then
		echo "Error: unable to extract $this_tar_dir exiting"
		exit 1
	fi

	if ! rm /tmp/docker_save_tmp.tar; then
		echo "Error: unable to delete temp file /tmp/docker_save_tmp.tar"
	fi

	mkdir -p "$this_tar_dir/combined/"
	find "$this_tar_dir" -name layer.tar \
		-exec tar --directory "$this_tar_dir/combined/" -xf {} \; 

	if [ ! -d "$this_tar_dir/combined/etc" ]; then
		echo "Error: Extraction failed. Exiting."
		exit 1
	fi
}

# Function create_tmp_dir() Creates a tmp dir if it doesn't exist and warns else
# input: this_location=$1
function create_tmp_dir() {
	this_location=$1
	if [ ! -d "$this_location" ]; then
		mkdir "$this_location"
	else
		echo "$this_location already exits, cowardly stopping"
		exit 1
	fi
}

#Function: set_docker_param(): set the param based on docker root
# input: return_val=$1      return variable
# input: aa_valid_params=$2 return associative array with valid parameters 
# input: param_to_lookup=$3 the key parameter to look up in $2 variable
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
	if [[ $DOCKER_TAG == "" ]]; then
		set_docker_param this_docker_tag aIMAGE_TAG "$this_docker_core"
	else
		this_docker_tag=$DOCKER_TAG
	fi

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
# input: $1 the full path to the file to check
# input: $2 the filename for where to save the hash file
# global: SECURITY_RISK_LEVEL
# global: SECURITY_WARNINGS
function docker_256sum_check() {
	local this_file_to_check=$1
	local this_file_of_hashes=$2
	local this_image_filename=""
	this_image_filename=$(basename "$this_file_to_check")

	print_v d "this_file_to_check=$this_file_to_check"
	print_v d "this_file_of_hashes=$this_file_of_hashes"
	print_v d "this_image_filename=$this_image_filename"

	if [[ $this_file_of_hashes != "" ]]; then
		print_v d "Checking Image of $this_image_filename"
		if ! grep "$this_image_filename" "$this_file_of_hashes" | awk -v tf="$this_file_to_check" '{print $1, tf}' | sha256sum --check --; then
			echo "Download of Vendor original source image failed hash check."
			echo "Failed hash check means also failed security audit. Exiting"
			exit 1
		fi
	else
		echo "Couldn't find vendor's source hash checks."
	fi
}

# Function: download_source_image
# input $this_uri=$1   remote location of image to download
# input $dir_prefix=$2 local directory to put image
function download_source_image() {
	local this_uri=$1
	local dir_prefix=$2
	#######Download Vendor Source Image
	if [[ $this_uri != "" ]]; then
		if [[ $DRY_RUN == 'false' ]]; then
			wget --directory-prefix="$dir_prefix" \
	             --force-directories \
	             -N  "$this_uri"
		else
			print_v v "Dry Run: Skipping download of $this_uri"
		fi
	
	else
		echo "Couldn't find vendor's source image file. Exiting."
		exit 1
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
	#local -n this_docker_vendor_image=$4
	local -n greatest_date=$4
	local local_hmsdate=""
	if [[ $1 = "" ]]; then
		"Error in getting core_url, exiting"
		exit 1
	fi
	
	for date_dir in $(wget -q --level=0 -O - "$core_url" | sed -e /current/d | grep folder | sed /.*href=\"/s/// | sed /\\/.*/s///); do
		local_hmsdate="${date_dir}000000"
		print_v d "Testing if $local_hmsdate, $date_dir <= $docker_date"
		if [ "$local_hmsdate" -le "$docker_date" ]; then
			print_v d "Yes $local_hmsdate <= $docker_date"
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

#####################################################################

#If called without args error out
if [[ ${#} -eq 0 ]]; then
	echo "Must be called with argument specifying client"
	print_usage
	exit 1
fi

DOCKER_CONTENT_TRUST=1
DOCKER_TAG=""
DEBUG='false'
VERBOSE='false'
optstring="hvndr:t:c:"
while getopts ${optstring} arg; do
	case ${arg} in
	c)
		DOCKER_CONTENT_TRUST="${OPTARG}"
	;;
	h)
		print_usage
		exit 0
	;;
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
	t)
		DOCKER_TAG="${OPTARG}"
		print_v v "Docker Tag not yet implemented $DOCKER_TAG"
	;;
	esac
done

print_v d "BASH_SOURCE=${BASH_SOURCE[0]}"
print_v d "PWD=$PWD"

setup_docker_globals "$DOCKER_ROOT"

#which image to analyze
#Notes; https://github.com/docker-library/repo-info/blob/master/repos/ubuntu/local/20.04.md


#Declare Associative Array Variables for various sources
#Notes: 
# Nvidia-base -> Ubuntu
# Nvidia-runtime-> nvidia-base -> Ubuntu
# gzserver -> Ubuntu
# libgazebo11 -> gzserver11 -> Ubuntu
declare -A aIMAGE_SOURCE_IMAGE_FILE
aIMAGE_SOURCE_IMAGE_FILE["ubuntu:focal"]="ubuntu-focal-core-cloudimg-amd64-root.tar.gz"
#aIMAGE_SOURCE_IMAGE_FILE["nvidia:11.0-base"]="https://gitlab.com/nvidia/container-images/cuda/blob/master/dist/11.2.2/ubuntu20.04-x86_64/runtime/cudnn8/Dockerfile"
aIMAGE_SOURCE_IMAGE_FILE["nvidia:11.0-base"]="https://gitlab.com/nvidia/container-images/cuda/-/raw/master/dist/11.2.2/ubuntu20.04-x86_64/base/Dockerfile"
aIMAGE_SOURCE_IMAGE_FILE["nvidia:11.2.2-runtime"]="https://gitlab.com/nvidia/container-images/cuda/-/raw/master/dist/11.2.2/ubuntu20.04-x86_64/runtime/Dockerfile"
#aIMAGE_SOURCE_IMAGE_FILE["gazebo:gzserver11"]="https://github.com/osrf/docker_images/blob/9cff18454e36bdaa182931c86a8c64205e51a2de/gazebo/11/ubuntu/focal/gzserver11/Dockerfile"
aIMAGE_SOURCE_IMAGE_FILE["gazebo:gzserver11"]="https://raw.githubusercontent.com/osrf/docker_images/master/gazebo/11/ubuntu/focal/gzserver11/Dockerfile"
aIMAGE_SOURCE_IMAGE_FILE["gazebo:gzserver11-focal"]="https://raw.githubusercontent.com/osrf/docker_images/master/gazebo/11/ubuntu/focal/gzserver11/Dockerfile"
#aIMAGE_SOURCE_IMAGE_FILE["gazebo:libgazebo11-focal"]="https://github.com/osrf/docker_images/blob/9cff18454e36bdaa182931c86a8c64205e51a2de/gazebo/11/ubuntu/focal/libgazebo11/Dockerfile"
aIMAGE_SOURCE_IMAGE_FILE["gazebo:libgazebo11-focal"]="https://raw.githubusercontent.com/osrf/docker_images/9cff18454e36bdaa182931c86a8c64205e51a2de/gazebo/11/ubuntu/focal/libgazebo11/Dockerfile"


declare -A aIMAGE_CORE
aIMAGE_CORE["ubuntu"]="partner-images.canonical.com/core/"
aIMAGE_CORE["nvidia"]="gitlab.com/nvidia/container-images/cuda/blob/master/dist/11.2.2/ubuntu20.04-x86_64/runtime/"
aIMAGE_CORE["gazebo"]="https://github.com/docker-library/repo-info/tree/master/repos/gazebo"

declare -A aIMAGE_TAG_DIR
aIMAGE_TAG_DIR["focal"]="focal/"
aIMAGE_TAG_DIR["11.0-base"]="cudnn8/"
aIMAGE_TAG_DIR["libgazebo11-focal"]="libgazebo11-focal"

# DockerCore: https://hub.docker.com/_/gazebo
# DockerCore: https://registry.hub.docker.com/r/nvidia/cuda
# DockerCore: https://registry.hub.docker.com/_/ubuntu
#gazebo:libgazebo11-focal
declare -A aIMAGE_BACKING_SOURCE
aIMAGE_BACKING_SOURCE["ubuntu:focal"]="ubuntu:focal"
aIMAGE_BACKING_SOURCE["nvidia:11.0-base"]="ubuntu:focal"
aIMAGE_BACKING_SOURCE["gazebo:libgazebo11-focal"]="ubuntu:focal"
#this_source_url=""
#print_v d " about to run aIMAGE_SOURCE_URL for $DOCKER_IMAGE, $THIS_DOCKER_TAG"
#set variable this_source_url (where we download the source docker image)
#set_docker_param this_source_url aIMAGE_SOURCE_URL "$DOCKER_IMAGE"
#print_v d "SOURCE URL= $this_source_url"

if [[ $THIS_DOCKER_PRODUCT != "" ]]; then
	IMAGE_VENDOR_PRODUCT="$THIS_DOCKER_CORE/$THIS_DOCKER_PRODUCT"
else
	IMAGE_VENDOR_PRODUCT="$THIS_DOCKER_CORE"
fi

#DOCKER_IMAGE set in setup_arrays
#DOCKER_IMAGE="$IMAGE_VENDOR_PRODUCT:${IMAGE_TAGS[$i]}"

#Download docker source image if it passes docker signing
print_v v "About to download docker image using 'sudo docker pull $DOCKER_IMAGE'"
if [[ $DOCKER_CONTENT_TRUST != 1 ]]; then
	SECURITY_RISK_LEVEL=$((SECURITY_RISK_LEVEL + 1))
	SECURITY_WARNINGS+=("Image not signed by notary.docker.io")
fi

if ! sudo DOCKER_CONTENT_TRUST="$DOCKER_CONTENT_TRUST" docker pull "$DOCKER_IMAGE"; then
	echo "Unable to download Docker Image. Exiting"
	if [[ $DOCKER_CONTENT_TRUST == 1 ]]; then
		echo "You used DOCKER_CONTENT_TRUST=1, try '-c 0' "
	fi
	exit 1
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

DOCKER_LOCAL_IMAGE_DIRECTORY="/srv/dockercheck/docker.$DOCKER_IMAGE.$IMAGE_CREATION_DATE"
if [ -d "$DOCKER_LOCAL_IMAGE_DIRECTORY" ]; then
	print_v v "Docker local image already saved"
else
	print_v v "Making Directory $DOCKER_LOCAL_IMAGE_DIRECTORY"
	mkdir "$DOCKER_LOCAL_IMAGE_DIRECTORY" || (echo "Error Can't make dir $DOCKER_LOCAL_IMAGE_DIRECTORY"; exit 1)
fi

THIS_DOCKER_VENDOR_IMAGE=""
which_docker_core_image "https://${aIMAGE_CORE[$THIS_DOCKER_CORE]}/${aIMAGE_TAG_DIR[$THIS_DOCKER_TAG]}" "$IMAGE_CREATION_DATE" "${aIMAGE_SOURCE_IMAGE_FILE[$DOCKER_IMAGE]}" THIS_DOCKER_VENDOR_DATE

if [[ $THIS_DOCKER_VENDOR_DATE == "" ]]; then
	echo "Error: No vendor date"
	exit 1
fi
THIS_DOCKER_VENDOR_IMAGE="${aIMAGE_CORE[$THIS_DOCKER_CORE]}/${aIMAGE_TAG_DIR[$THIS_DOCKER_TAG]}/$THIS_DOCKER_VENDOR_DATE/${aIMAGE_SOURCE_IMAGE_FILE[$DOCKER_IMAGE]}"
THIS_DOCKER_VENDOR_HASH="${aIMAGE_CORE[$THIS_DOCKER_CORE]}/${aIMAGE_TAG_DIR[$THIS_DOCKER_TAG]}/$THIS_DOCKER_VENDOR_DATE/SHA256SUMS"
THIS_DOCKER_VENDOR_IMAGE_URL="https://$THIS_DOCKER_VENDOR_IMAGE"
THIS_DOCKER_VENDOR_HASH_URL="https://$THIS_DOCKER_VENDOR_HASH"

print_v d "DOCKER_IMAGE=$DOCKER_IMAGE"
print_v d "THIS_DOCKER_TAG=$THIS_DOCKER_TAG"
print_v d "THIS_DOCKER_VENDOR_DATE=$THIS_DOCKER_VENDOR_DATE"
print_v d "THIS_CORE_DIR=${aIMAGE_CORE[$THIS_DOCKER_CORE]}"
print_v d "THIS_TAG_DIR=${aIMAGE_TAG_DIR[$THIS_DOCKER_TAG]}"
print_v d "IMAGE_CREATION_DATE=$IMAGE_CREATION_DATE"
print_v d "THIS_DOCKER_VENDOR_IMAGE=$THIS_DOCKER_VENDOR_IMAGE"
print_v d "aIMAGE_BACKING_SOURCE=${aIMAGE_BACKING_SOURCE[$DOCKER_IMAGE]}"


print_v v "Checking $DOCKER_IMAGE"
print_v v "Source Image Identified as: ${aIMAGE_SOURCE_IMAGE_FILE[${DOCKER_IMAGE}]}"
#print_v v "Source URL Identified as: ${aIMAGE_SOURCE_URL[${DOCKER_IMAGE}]}"


if [[ ${aIMAGE_SOURCE_IMAGE_FILE[$DOCKER_IMAGE]} =~ "Dockerfile" ]]; then
	echo -n "This docker image doesn't use their own core image. "
	echo -n "E.g. Nvidia uses a DockerFile that references Ubuntu/UBI/CentOS cores. "
	echo "Getting DockerFile"
	DO_HASH_CHECK='false'
	DOCKERFILE_ONLY='true'
	if [[ $DRY_RUN == 'false' ]]; then
		wget -O /tmp/latest_docker_file.dockerfile "$this_uri"
	else
		print_v v "Dry Run: Skipping download of $this_uri"
	fi
else 
	DOCKERFILE_ONLY='false'
	print_v v "About to download $THIS_DOCKER_VENDOR_IMAGE_URL"
	download_source_image "$THIS_DOCKER_VENDOR_IMAGE_URL" $LOCAL_VENDOR_ROOT_DIR

	if [[ $THIS_DOCKER_VENDOR_HASH_URL == "" ]]; then
		SECURITY_RISK_LEVEL=$((SECURITY_RISK_LEVEL + 1))
		SECURITY_WARNINGS+=("Image not signed by vendor")
		DO_HASH_CHECK='false'
	else 
		download_source_image "$THIS_DOCKER_VENDOR_HASH_URL" $LOCAL_VENDOR_ROOT_DIR
		DO_HASH_CHECK='true'
	fi
fi

if [[ $DO_HASH_CHECK == 'true' ]]; then
	#check downloaded file image passes hash checks
	docker_256sum_check "$LOCAL_VENDOR_ROOT_DIR/$THIS_DOCKER_VENDOR_IMAGE" "$LOCAL_VENDOR_ROOT_DIR/$THIS_DOCKER_VENDOR_HASH"
fi

# Extracting the layers and then extracting the layers all to one combined directory.
# Then analyze shared image to vendor core image
print_v v "About to do security comparison of $LOCAL_VENDOR_ROOT_DIR/$THIS_DOCKER_VENDOR_IMAGE and $DOCKER_IMAGE"

##Extract Tmp Dirs for security analysis
DATETIME=$(date +%Y%m%d.%H%M)
DOCKER_DELIVERED_TAR_DIR="/tmp/dockerd_img_extract.$DATETIME"
DOCKER_VENDOR_TAR_DIR="/tmp/dockerv_img_extract.$DATETIME"

create_tmp_dir "$DOCKER_DELIVERED_TAR_DIR"
create_tmp_dir "$DOCKER_VENDOR_TAR_DIR"

print_v d "Created tmp dirs ok"

CAN_DO_DIFF='true'
if ! extract_docker_image "$LOCAL_VENDOR_ROOT_DIR/$THIS_DOCKER_VENDOR_IMAGE" "$DOCKER_DELIVERED_TAR_DIR"; then
	CAN_DO_DIFF='false'
	print_v d "Cannot do diff as extract_docker_image to $DOCKER_DELIVERED_TAR_DIR failed"
else
	print_v d "Extract_docker_image to $DOCKER_DELIVERED_TAR_DIR ok"
fi

if ! tar -zxf "$DOCKER_IMAGE" --directory "$DOCKER_VENDOR_TAR_DIR"; then
	CAN_DO_DIFF='false'
	print_v d "Cannot do diff as tar extraction of $DOCKER_VENDOR_TAR_DIR failed"
fi


if [[ $CAN_DO_DIFF == 'true' ]]; then
	# shellcheck disable=1091
	source ./SCAP_docker.sh "$DOCKER_DELIVERED_TAR_DIR" "$DOCKER_VENDOR_TAR_DIR"
fi

print_final_report

# tabs instead of spaces in bash scripts for heredoc <<-
# vim: ts=4 noexpandtab
