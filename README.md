# Installing Kubernetes, the less hard way.

A wrapper script which installs Kubernetes masters and workers on Ubuntu-based VM's, complete with kube-router (no kube-proxy) and CoreDNS.

Starting off with a freshly installed Ubuntu Cloud VM image (see my [virthelper](https://github.com/jforman/virthelper) script), install Kubernetes using Kubeadm. This wrapper automates installing controller and worker nodes, removing kube-proxy (in favor of [kube-router](https://github.com/cloudnativelabs/kube-router)).

## Script Usage

```bash
usage: kubify.py [-h] --config CONFIG [--dry_run] [--debug]
                 [--kubeadm_init_extra_flags KUBEADM_INIT_EXTRA_FLAGS]
                 [--local_storage_dir LOCAL_STORAGE_DIR]

Install Kubernetes cluster with kubeadm

optional arguments:
  -h, --help            show this help message and exit
  --config CONFIG       kubify config file. (default: None)
  --dry_run             dont actually do anything. (default: False)
  --debug               enable debug-level logging. (default: False)
  --kubeadm_init_extra_flags KUBEADM_INIT_EXTRA_FLAGS
                        Additional flags to add to kubeadm init step.
                        (default: None)
  --local_storage_dir LOCAL_STORAGE_DIR
                        Local on-disk directory to store configs,
                        certificates, etc (default: None)
```
## Configuration File

Below is an example kubify.conf config file, with a minimum configuration specified.

```bash
# Kubify Configuration File
# Prod
# Cluster CIDR: IP range used by inter-pod inter-cluster transit.
# Service CIDR: IP range used by Services on the cluster.

[general]
api_server_loadbalancer_hostport=10.10.200.104:443
cluster_name=prod
domain_name=foo.basement.net
pod_subnet=10.88.0.0/16
service_subnet=10.122.0.0/16
cluster_dns_ip_address=10.122.0.10

[controller]
remote_user=ubuntu
prefix=prod-controller
ip_addresses=10.10.200.105,10.10.200.106,10.10.200.107

[worker]
remote_user=ubuntu
prefix=prod-worker
ip_addresses=10.10.200.108,10.10.200.109,10.10.200.110
```
