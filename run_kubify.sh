#!/bin/bash -x

# Args:
#   $1: Path to kubify configuration file.
#   $2: Directory containing kubectl binary, certificate, and config files.
#   $3*: Parameters to actual kubify execution.

# Example
# /run_kubify.sh kubify-prod.conf \
#   /nas1/code/kubernetes/prod \
#   upgrade \
#   --debug --k8s_version 1.20 --dry_run

docker build -t jforman/kubify:latest .

docker run -it --rm \
-e SSH_AUTH_SOCK=/ssh-agent \
-v ${SSH_AUTH_SOCK}:/ssh-agent \
-v ~/.ssh:/root/.ssh:ro \
-v `realpath $1`:/kubify-config:ro \
-v $2:/rundir jforman/kubify:latest \
./kubify.py --local_storage_dir /rundir --config /kubify-config ${@:3}
