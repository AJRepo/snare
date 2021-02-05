# docker_image_checks
Review Docker images to check for issues (primarily security issues) prior to container activation. 

This script was built up to automate checks after finding an unsigned binary added to an officially released docker image between a github code release and the docker preparation. This was undetectible without a deep dive tar analysis as both images were signed. 

This code is distributed under a dual license: an open source license, and a commercial license. The open source license is distributed is the GNU Public License version 3 (GPLv3) for any usage that is non-commerical. For commercial licensing please contact via email or github issues. 

