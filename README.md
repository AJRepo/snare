# docker_image_checks

Review Docker images to check for issues (primarily security issues) prior to container activation.

This script was built up to automate checks after finding an unsigned binary added to an officially released docker image between a vendors github code release and the docker preparation. This was undetectible without a deep dive tar analysis as both images were signed.

This code is distributed under a dual license: an open source license, and a commercial license. The open source license is distributed is the GNU Public License version 3 (GPLv3) for any usage that is non-commerical. For commercial or government licensing please contact via email or github issues.

This script uses wget's functionality to do a comparison between the online version of the vendor's core docker image and a local cached download. If the vendor's source image differs from the local copy (or if the local copy doesn't exist) then this script downloads the vendor source image. This can be overridden with -l (Local only) but since wget does the check to see if there's a change between the vendor's source and the local cache, using the -l flag is not recommended. 

This script then compares the local cached image to the docker image and then runs checkis to see what changes the docker containerization script has implemented.

This requires the commands "docker", "tar" and "wget" to be available on the testing machine (as well as the usual Bash tools like awk/sed/grep/etc). 

It does not run any docker containers, and allows analyzing the containers before they are run.

How to use:

```
Usage: docker_image_check.sh
   -c <0|1>    DOCKER_CONTENT_TRUST= (defaults to 1)
   -d          Debug mode (print more)
   -h          Help
   -v          Verbose mode (print more)
   -l          Local saved archive of core vendor image instead of using wget
   -n          Dry Run (do not download)
   -r <name>   Root docker image to analyze (nvida, ubuntu)
   -t <name>   Docker tag to analyze (e.g. focal)
```

# Notes:
  DOCKER_CONTENT_TRUST=1 with "docker pull" causes an older version to be pulled. That version might not be available if the auto generated mirrors don't go back far enough in time. See: https://github.com/tianon/docker-brew-ubuntu-core/issues/204

  The Docker Image format specifications appears to not be well documented. There is an open spec at https://github.com/opencontainers/image-spec

# Examples:

**Ubuntu Focal (20.04) with DOCKER_CONTENT_TRUST=0:** ./docker_image_check.sh -c 0 -d -v -r ubuntu -t focal
