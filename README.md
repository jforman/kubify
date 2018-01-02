# Installing Kubernetes, the hard way.

Based on https://github.com/kelseyhightower/kubernetes-the-hard-way

This script is meant to follow Kelsey Hightower's tutorial of installing Kubernetes. It was born out of the fact that I run CoreOS VM's at home on a Ubuntu (sometimes Debian) libvirt/kvm server, and wish to play around with CoreOS+Kubernetes tech at home. None of the other tutorials I found online spent much time on bare-metal, or in this case VM, installs. Most other scripts expected the Kubernetes cluster to live on one of the popular public clouds (GCE/AWS/Azure), and I wanted to do have my own install on my own terms.

Why not the public cloud? Mostly because of cost. I've already got a beefy VM server at home. Why not use it?

## Script Usage

usage: kubify.py [-h] [--dry_run] [--kube_ver KUBE_VER] --output_dir
                 OUTPUT_DIR [--clear_output_dir]

Install Kubernetes, the hard way.

optional arguments:
  -h, --help            show this help message and exit
  --dry_run             dont actually do anything. (default: False)
  --kube_ver KUBE_VER   kubernetes version (default: 1.9.0)
  --output_dir OUTPUT_DIR
                        base directory where generated configs will be stored.
                        (default: None)
  --clear_output_dir    if true, clear the output directory before generating
                        configs (default: False)


### Shortcuts in the script

Given the cfssl and cfssljson commands use a lot of the same directory paths and file references, I've declared the following special variables which will be replaced accordingly when those commands are run.

{CHECKOUT_DIR}: Git checkout directory
{OUTPUT_DIR}: Directory were certificates and other generated data will be stored.

{ADMIN_DIR}: Directory under OUTPUT_DIR where administrative certificates are stored.
{BIN_DIR}: Directory under OUTPUT_DIR where binaries related to configuration generation will live.
{CA_DIR}: Directory under OUTPUT_DIR where certificate authority certificates are stored.
{TEMPLATE_DIR}: Directory under Git checkout where JSON and other configuration templates lives.
{TMP_DIR}: Directory under OUTPUT_DIR where intermediate output is stored that can be later consumed by other processes.
