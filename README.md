# Installing Kubernetes, the hard way.

Based on https://github.com/kelseyhightower/kubernetes-the-hard-way

This script is meant to follow Kelsey Hightower's tutorial of installing Kubernetes. It was born out of the fact that I run CoreOS VM's at home on a Ubuntu (sometimes Debian) libvirt/kvm server, and wish to play around with CoreOS+Kubernetes tech at home. None of the other tutorials I found online spent much time on bare-metal, or in this case VM, installs. Most other scripts expected the Kubernetes cluster to live on one of the popular public clouds (GCE/AWS/Azure), and I wanted to do have my own install on my own terms.

Why not the public cloud? Mostly because of cost. I've already got a beefy VM server at home. Why not use it?

## Script Usage

```bash
usage: kubify.py [-h] [--clear_output_dir] [--config CONFIG] [--dry_run]
                 [--debug] [--kube_ver KUBE_VER] --output_dir OUTPUT_DIR

Install Kubernetes, the hard way.

optional arguments:
  -h, --help            show this help message and exit
  --clear_output_dir    delete the output directory before generating configs
                        (default: False)
  --config CONFIG       kubify config file. (default: None)
  --dry_run             dont actually do anything. (default: False)
  --debug               enable debug-level logging. (default: False)
  --kube_ver KUBE_VER   kubernetes version (default: 1.9.0)
  --output_dir OUTPUT_DIR
                        base directory where generated configs will be stored.
                        (default: None)
```
## Configuration File

Below is an example kubify.conf config file, with a minimum configuration specified.

```bash
# Kubify Configuration File
# Cluster CIDR: IP range used by inter-pod inter-cluster transit.
# Service CIDR: IP range used by Services on the cluster.

[general]
api_server_ip_address=10.10.2.119
cluster_name=corea
domain_name=foo.basement.net
install_dir=/opt/kubernetes
ssl_certs_dir=/etc/ssl/certs/
cluster_cidr=10.244.0.0/16
service_cidr=10.122.0.0/16
cluster_dns_ip_address=10.122.0.10

[controller]
remote_user=core
prefix=corea-controller
ip_addresses=10.10.0.125,10.10.0.126,10.10.0.127

[worker]
remote_user=core
prefix=corea-worker
ip_addresses=10.10.0.110,10.10.0.111,10.10.0.112,10.10.0.113,10.10.0.114
```

