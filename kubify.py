#!/usr/bin/env python3

import argparse
import base64
import configparser
import inspect
import ipaddress
import json
import logging
import os
import paramiko
import re
import shutil
import string
import subprocess
import sys
import time
import traceback
import urllib.request
import yaml

import helpers
from packaging import version

RE_CERTIFICATE_KEY = re.compile(r'--certificate-key (\S+)', re.MULTILINE)
RE_DISCOVERY_TOKEN = re.compile(r'--discovery-token-ca-cert-hash (\S+)', re.MULTILINE)
RE_TOKEN = re.compile(r'--token (\S+)', re.MULTILINE)
RE_CERTIFICATE_KEY_REINIT = re.compile(r'Using certificate key:\s+(\S+)', re.MULTILINE)

class KubeBuild(object):
    """define, create, and deploy a kubernetes cluster methods."""

    def __init__(self, cli_args):

        def read_config(config_path):
            if not os.path.exists(config_path):
                logging.fatal(f"Unable to read config file at {config_path}.")
                raise
            logging.info(f"Reading config at {config_path}.")
            c = configparser.ConfigParser()
            c.read(config_path)
            return c

        self.args = cli_args
        self.checkout_path = os.path.dirname(os.path.realpath(sys.argv[0]))
        self.config = read_config(self.args.config)

        self.node_pod_cidrs = {}
        # Directories pertaining to checkout and output directory
        # configurations.
        self.kubify_dirs = {}
        self.set_k8s_paths()
        self.k8s_version = None

        # arguments to the kubeadm join command for other nodes
        self.join_token = ""
        self.discovery_token_ca_cert_hash = ""
        self.certificate_key = ""

        logging.debug(f'Checkout Path: {self.checkout_path}')

    def timeit(method):

        def timed(*args, **kwargs):
            start_time = time.time()
            result = method(*args, **kwargs)
            end_time = time.time()
            elapsed_time = end_time - start_time
            logging.debug(f'execution info: method: {method.__name__}, elapsed: {elapsed_time:0.3f}s.')
            return result

        return timed

    def get_latest_k8s_patch_version(self, r_version_str):
        """given a major.minor version, find the latest patch version available."""
        f = urllib.request.urlopen("https://api.github.com/repos/kubernetes/kubernetes/releases")
        raw_output = f.read().decode().strip()
        rel_json = json.loads(raw_output)
        r_version_obj = version.Version(r_version_str)
        candidates = []
        for candidate in rel_json:
            c_tag_name = candidate['tag_name']
            if c_tag_name.startswith(f"v{r_version_obj.public}"):
                logging.debug(f"Found candidate for version: {c_tag_name}.")
                if '-rc' in c_tag_name:
                    continue
                # TODO: add --allow_prereleases to kubify to allow preleases?
                candidates.append(version.Version(c_tag_name))
        candidates = sorted(candidates)
        logging.info(f"Candidates: {candidates}.")
        latest = candidates[-1]
        logging.info(f"Latest candidate: {latest.public}")
        return latest.public

    def get_k8s_full_code_version(self, remote_user, node_ip, mmp_version_str):
        """given major.minor.patch k8s version, find the packaged code version."""
        logging.info("Getting full code version.")
        command_output = self.run_command_via_ssh_paramiko(
            remote_user,
            node_ip,
            'apt list kubelet',
            noop_command=True,
            return_output=True)

        # TODO: this regex seems overly lenient. figure out why kubelet/unknown
        # wouldn't match.
        search_string = f"kubelet.* ({mmp_version_str}-\S+.\S+) amd64"
        logging.debug(f"Search string: {search_string}")
        full_code_ver = re.search(search_string, command_output, re.MULTILINE).group(1)
        logging.info(f"Found latest code version: {full_code_ver}")

        return full_code_ver


    def get_k8s_version(self, raw_version=None):
        """parse the requested kubernetes version into self.k8s_version."""
        ver_obj = version.Version

        if self.k8s_version is not None:
            logging.info(f"Found cached k8s_version: {self.k8s_version}. Returning.")
            return self.k8s_version

        logging.debug(f"k8s version passed on command line: {self.args.k8s_version}")

        if all([
            len(self.args.k8s_version.split('.')) == 3,
            self.args.k8s_version.split('.')[-1] == '0'
            ]):
            logging.info(f"Requested to install micro version 0 of release {ver_obj.major}.{ver_obj.minor}.")
            ver_obj = version.Version(self.args.k8s_version)
        elif (self.args.k8s_version.startswith('latest-') or self.args.k8s_version.startswith('stable-')):
            f = urllib.request.urlopen(f"https://dl.k8s.io/release/{self.args.k8s_version}.txt")
            raw_version = f.read().decode().strip()
            ver_obj = version.Version(raw_version)
        else:
            ver_obj = version.Version(self.args.k8s_version)
            logging.info(f"Only provided with major and minor version. Determing latest micro version for k8s version: {ver_obj.major}.{ver_obj.minor}.")
            if ver_obj.micro == 0:
                ver_obj = version.Version(self.get_latest_k8s_patch_version(f"{ver_obj.major}.{ver_obj.minor}"))
                logging.info(f"Latest patch version for k8s version {ver_obj.major}.{ver_obj.minor} determined to be: {ver_obj.public}.")

        logging.info(f"k8s_version parsed to {ver_obj}.")
        self.k8s_version = ver_obj
        return self.k8s_version

    @timeit
    def set_k8s_paths(self):
        """given string containing special macro, return command line with
        directories substituted in string."""
        self.kubify_dirs['CHECKOUT_DIR'] = os.path.dirname(os.path.realpath(sys.argv[0]))
        self.kubify_dirs['CHECKOUT_CONFIG_DIR'] = os.path.join(
            self.kubify_dirs['CHECKOUT_DIR'], 'configs')
        self.kubify_dirs['TEMPLATE_DIR'] =  os.path.join(
            self.kubify_dirs['CHECKOUT_DIR'], 'templates')

    @timeit
    def scp_file(self, local_path, remote_user, remote_host, remote_path,
                 ignore_errors=False):
        """copy the local file to the remote destination."""
        ssh_args = "-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
        if self.args.dry_run:
            logging.info(f"DRY RUN: Would have copied local file {local_path}, "
                         f"to {remote_host}:{remote_path}.")
            return

        if not os.path.exists(local_path):
            logging.fatal(f"Went to copy local file {local_path}, but file not found.")
            raise
        else:
            logging.debug(f"Local file {local_path} found.")

        self.run_command(
            f"scp {ssh_args} {local_path} "
            f"{remote_user}@{remote_host}:{remote_path}",
            ignore_errors=ignore_errors,
        )

    @timeit
    def scp_get_via_paramiko(self, remote_user, remote_host, remote_path, local_path):
        """copy local file to remote destination."""
        logging.info(f"Attempting to retrieve {remote_user}@{remote_host}:{remote_path} to {local_path}.")
        if self.args.dry_run:
                logging.info(f"DRY RUN: Would have copied {local_path} to {remote_host}:{remote_path}.")
                return
        file_basename = os.path.basename(local_path)
        logging.debug(f"SCP file basename: {file_basename}")
        try:
            # heavily adopted from
            # https://stackoverflow.com/questions/3635131/paramikos-sshclient-with-sftp#66724076
            logging.debug(f"Creating paramiko SSH client.")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(remote_host, username=remote_user)
            sftp = client.open_sftp()
            sftp.get(remote_path, local_path)
        except Exception as e:
            logging.fatal(f"Error when getting file via SFTP: {e}.")
            logging.debug(f"Closing sftp client.")
            sftp.close()
            raise

        logging.info(f"Done retrieving file.")

    @timeit
    def scp_put_via_paramiko(self, local_path, remote_user, remote_host,
                             remote_path, noop_command=False):
        """copy local file to remote destination."""
        # heavily adopted from
        # https://stackoverflow.com/questions/3635131/paramikos-sshclient-with-sftp#66724076

        if self.args.dry_run:
                logging.info(f"DRY RUN: Would have copied {local_path} to {remote_host}:{remote_path}.")
                return

        logging.debug(f"Creating paramiko SSH client.")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(remote_host, username=remote_user)
        sftp = client.open_sftp()

        try:
            file_basename = os.path.basename(local_path)
            sftp.put(local_path, file_basename)
            self.run_command_via_ssh_paramiko(
                remote_user, remote_host,
                f"sudo cp {file_basename} {remote_path}")
        except Exception as e:
            logging.fatal(f"Error in SFP put: {e}.")
            logging.debug(f"Closing sftp client.")
            sftp.close()
            raise

        logging.info(f"Done uploading file via SFTP.")

    @timeit
    def run_command_via_ssh_paramiko(self, remote_user, remote_host, command,
                                     ignore_errors=False, return_output=False,
                                     noop_command=False):
        if self.args.dry_run:
            if noop_command:
                logging.info(f"DRY RUN AND NOOP: Execute: { command }")
            else:
                # If we run dry run, but it's a command that will mutate things,
                # dont run it.
                logging.info(f"DRY RUN AND MUTATE: Don't Execute: { command }")
                return

        logging.info(f"Executing command via paramiko on {remote_host}: {command}")
        logging.debug(f"Creating paramiko SSH client.")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(remote_host, port=22, username=remote_user)
        stdin, stdout, stderr = client.exec_command(command)

        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')
        logging.debug(f"Paramiko stdout: {output}")
        logging.debug(f"Paramiko stderr: {error}")
        client.close()
        logging.debug(f"Closing paramiko SSH client.")

        if return_output:
            return output

    @timeit
    def run_command_via_ssh(self, remote_user, remote_host, command,
                            ignore_errors=False, return_output=False, noop_command=False):
        """ssh to remote host and run specified command."""
        ssh_args = ('-o UserKnownHostsFile=/dev/null '
                    '-o StrictHostKeyChecking=no '
                    '-t')

        output = self.run_command(
            f"ssh {ssh_args} {remote_user}@{remote_host} {command}",
            ignore_errors=ignore_errors,
            return_output=return_output,
            noop_command=noop_command,
            )

        if return_output:
            return output


    @timeit
    def write_template(self, input_template, output_path, template_vars):
        """write a jinja2 template, with support for dry run and logging."""

        output = helpers.render_template(
            input_template,
            template_vars)

        if self.args.dry_run:
            logging.info(f"DRYRUN: Write template "
                         f"{input_template} to {output_path}")
        else:
            with open(output_path, 'w') as output_file:
                output_file.write(output)

    @timeit
    def check_upgrade_viability(self, dest_k8s_ver):
        """given a desired k8s version, return true if we can upgrade to it."""
        dest_k8s_ver_obj = self.get_k8s_version(raw_version=dest_k8s_ver)
        logging.info(f"Checking status of nodes to see if upgrade to to {dest_k8s_ver_obj} is possible.")

        kubectl_getnodes_output = self.run_command(
            f"{self.args.local_storage_dir}/kubectl "
            f"--kubeconfig={self.args.local_storage_dir}/admin.conf "
            "get nodes -o yaml",
            return_output=True,
            noop_command=True)
        nodes_yaml = yaml.safe_load(kubectl_getnodes_output)
        node_versions = []
        for cur_node in nodes_yaml['items']:
            node_name = cur_node['metadata']['labels']['kubernetes.io/hostname']
            node_ver = cur_node['status']['nodeInfo']['kubeletVersion']
            node_versions.append(node_ver)
            logging.info(f"Found node {node_name} running kubelet version {node_ver}.")
        node_versions = set(node_versions)
        logging.info(f"Cluster found running versions: {node_versions}.")

        # TODO: add logic to bail when there are nodes of two different minor versions.
        # this is an un-upgradable scenario because one could be skipping a minor version.
        for c in node_versions:
            c_ver = version.Version(c)
            logging.debug(f"Determining if upgrade from {c_ver.public} to {dest_k8s_ver_obj} is possible.")
            if c_ver is None:
                logging.fatal(f'unable to determine node version dictionary: {c}')
            if dest_k8s_ver_obj.major != c_ver.major:
                logging.fatal(f'attempting an upgrade across major versions is not supported. '
                              f'attemped to upgrade to: {self.get_k8s_version().public}, but found: {c}')
            minor_ver_diff = int(dest_k8s_ver_obj.minor) - int(c_ver.minor)
            if minor_ver_diff > 1:
                logging.exception('attempting to skip minor version upgrade. currently unsupported by kubeadm.')
                raise
            logging.info(f"Viable upgrade path for {c_ver.public} to {dest_k8s_ver_obj}.")
        return True

    @timeit
    def get_nodes_from_cluster(self, node_type):
        """given node_type, return list of tuples (node_name, node_ip) from cluster."""
        nodes = []
        if node_type == 'controller':
            selector = "node-role.kubernetes.io/control-plane"
        elif node_type == 'worker':
            selector = "!node-role.kubernetes.io/control-plane"
        else:
            logging.error(f"Attempting to retrieve cluster nodes of type '{node_type}' which is unsupported.")
            sys.exit(1)

        kubectl_getnodes_output = self.run_command(
            f"{self.args.local_storage_dir}/kubectl get nodes "
            f"--kubeconfig={self.args.local_storage_dir}/admin.conf "
            f"--selector={selector} "
            f"-o json",
            return_output=True,
            noop_command=True)

        getnodes_json = json.loads(kubectl_getnodes_output)

        for candidate_node in getnodes_json["items"]:
            if candidate_node["kind"] == "Node":
                node_name = candidate_node["metadata"]["name"]
                for addresses in candidate_node["status"]["addresses"]:
                    # NOTE: Is there possiblity of multiple IP addresses on a node?
                    # This code only handles first one.
                    if addresses["type"] == "InternalIP":
                        node_ip_address = addresses["address"]
                        nodes.append((node_name, node_ip_address))
        logging.info(f"Nodes Found: Type {node_type}. List: {nodes}.")
        return nodes

    @timeit
    def deploy_containerd(self, node_ip, node_user, apt_command):
        self.run_command_via_ssh_paramiko(
            node_user,
            node_ip,
            f'sudo apt {apt_command} -y containerd.io')

        self.scp_put_via_paramiko(
            f"{self.kubify_dirs['CHECKOUT_CONFIG_DIR']}/etc/containerd/config.toml",
            node_user,
            node_ip,
            "/etc/containerd/config.toml")

        self.run_command_via_ssh_paramiko(
            node_user,
            node_ip,
            'sudo systemctl enable containerd')

        self.run_command_via_ssh_paramiko(
            node_user,
            node_ip,
            'sudo systemctl restart containerd')


    @timeit
    def upgrade_worker_nodes(self):
        """upgrade worker nodes to new kubernetes version."""
        k8s_version = self.get_k8s_version()
        node_type = 'worker'

        for node_name, node_ip in self.get_nodes_from_cluster(node_type):
            logging.info(f"upgrading kubernetes worker node {node_name} (ip: {node_ip}) to {k8s_version.public}.")

            self.update_apt_repos(node_type, node_ip)
            full_code_version = self.get_k8s_full_code_version(
                self.config.get(node_type, 'remote_user'),
                node_ip,
                k8s_version)

            self.run_command_via_ssh_paramiko(
                self.config.get(node_type, 'remote_user'),
                node_ip,
                f"sudo apt-mark unhold kubeadm && "
                f"sudo apt install -y kubeadm={full_code_version} && "
                f"sudo apt-mark hold kubeadm")

            self.run_command_via_ssh_paramiko(
                self.config.get(node_type, 'remote_user'),
                node_ip,
                f"sudo kubeadm upgrade node")

            self.upgrade_kubernetes_binaries('worker', specific_node=node_ip)

    @timeit
    def upgrade_control_plane(self, k8s_ver):
        """upgrade k8s control plane to new k8s version."""
        first_node_done=False
        node_type='controller'
        k8s_ver = self.get_k8s_version()

        for node_name, node_ip in self.get_nodes_from_cluster(node_type):
            logging.info(f"Starting upgrade_control_plane for {node_name} (ip: {node_ip}).")

            self.update_apt_repos(node_type, node_ip)

            full_code_version = self.get_k8s_full_code_version(
                self.config.get(node_type, 'remote_user'),
                node_ip,
                k8s_ver)

            self.run_command_via_ssh_paramiko(
                self.config.get(node_type, 'remote_user'),
                node_ip,
                f"sudo apt-mark unhold kubeadm={full_code_version} && "
                f"sudo apt install -y kubeadm={full_code_version} && "
                f"sudo apt-mark hold kubeadm")

            remote_k8s_version = self.run_command_via_ssh_paramiko(
                self.config.get(node_type, 'remote_user'),
                node_ip,
                "kubeadm version -o yaml",
                return_output = True)

            if self.args.dry_run:
                logging.info("DRY RUN: Would have retrieved remote kubeadm version.")
                logging.info("DRY RUN: Would have checked that remote kubeadm version matched what we expected.")
            else:
                remote_version_yaml = yaml.safe_load(remote_k8s_version)
                remote_version = self.get_k8s_version(
                    raw_version=remote_version_yaml['clientVersion']['gitVersion'])
                if k8s_ver != remote_version:
                    logging.fatal(f"Installed kubeadm version mismatch. "
                                    f"Expected: {k8s_ver}. Found: {remote_version}.")

            if first_node_done is False:
                # Only commands to run on the first control node.
                self.run_command_via_ssh_paramiko(
                    self.config.get(node_type, 'remote_user'),
                    node_ip,
                    'sudo kubeadm upgrade plan')

                self.run_command_via_ssh_paramiko(
                    self.config.get(node_type, 'remote_user'),
                    node_ip,
                    f"sudo kubeadm upgrade apply --yes v{k8s_ver.public}")

                self.deploy_flannel()
                first_node_done = True
            else:
                # Commands for all the other control nodes.
                self.run_command_via_ssh_paramiko(
                    self.config.get(node_type, 'remote_user'),
                    node_ip,
                    f"sudo kubeadm upgrade node")
        logging.info("finished upgrade_control_plane")

    @timeit
    def get_nodes(self, node_type, node_source=""):
        """given a node type, return a list of hosts of that node type.
        if node_source=="config", the nodes are always retrieved from config.
            needed when adding a node to a pre-existing cluster.
        """
        nodes = []

        if self.args.node and node_source=="":
            logging.debug("Getting node information from command line flags.")
            for node in self.args.node:
                (new_node_type, new_node_hostname) = node.split(':')
                if new_node_type == node_type:
                    nodes.append(new_node_hostname)
            return nodes

        logging.debug("Getting node information from config.")
        nodes = self.config.get(node_type, 'ip_addresses').split(',')
        logging.debug(f"Node {node_type} IPs: {nodes}")

        return nodes

    @timeit
    def reboot_hosts(self, node_type):
        """reboot a set of hosts."""
        for node in self.get_nodes(node_type):
            logging.info(f"rebooting host {node}.")
            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                node,
                'sudo shutdown -r now',
                ignore_errors=True)

    @timeit
    def update_apt_repos(self, node_type, node_ip=None):
        """deploy apt repo configs and update apt repositories on node."""
        k8s_version = self.get_k8s_version()

        if node_ip:
            node_list=[node_ip]
        else:
            node_list=self.get_nodes(node_type, node_source="config")

        for node in node_list:
            logging.info(f"Updating APT repositories on node {node}.")
            self.run_command_via_ssh_paramiko(
                self.config.get(node_type, 'remote_user'),
                node,
                'sudo mkdir -p /etc/apt/keyrings')

            self.write_template(
                f"{self.kubify_dirs['TEMPLATE_DIR']}/etc/apt/sources.list.d/kubernetes.list.j2",
                f"{self.kubify_dirs['CHECKOUT_CONFIG_DIR']}/kubernetes.list",
                {
                    'major': self.get_k8s_version().major,
                    'minor': self.get_k8s_version().minor,
                })

            # Kubernetes Repository
            self.scp_put_via_paramiko(
                f"{self.kubify_dirs['CHECKOUT_CONFIG_DIR']}/kubernetes.list",
                self.config.get(node_type, 'remote_user'),
                node,
                f"/etc/apt/sources.list.d/kubernetes-v{self.get_k8s_version().major}.{self.get_k8s_version().minor}.list")

            self.run_command_via_ssh_paramiko(
                self.config.get(node_type, 'remote_user'),
                node,
                f"curl -fsSLo /tmp/kubernetes-archive-keyring.gpg https://pkgs.k8s.io/core:/stable:/v{k8s_version.major}.{k8s_version.minor}/deb/Release.key",
            )

            self.run_command_via_ssh_paramiko(
                self.config.get(node_type, 'remote_user'),
                node,
                "sudo gpg --dearmor --batch --yes -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg /tmp/kubernetes-archive-keyring.gpg"
            )

            # Docker Repository
            self.run_command_via_ssh_paramiko(
                self.config.get(node_type, 'remote_user'),
                node,
                'sudo wget -O /tmp/docker-gpg-key https://download.docker.com/linux/ubuntu/gpg')

            self.run_command_via_ssh_paramiko(
                self.config.get(node_type, 'remote_user'),
                node,
                'sudo gpg --batch --yes -o /etc/apt/trusted.gpg.d/docker-archive-keyring.gpg --dearmor /tmp/docker-gpg-key')

            self.run_command_via_ssh_paramiko(
                self.config.get(node_type, 'remote_user'),
                node,
                'echo \"deb [arch=amd64 signed-by=/etc/apt/trusted.gpg.d/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable\" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null')

            self.run_command_via_ssh_paramiko(
                self.config.get(node_type, 'remote_user'),
                node,
                "sudo apt update")
            logging.info(f"Done updating APT repositories on node {node}.")

    @timeit
    def deploy_container_runtime(self, node_type, apt_command='install'):
        """deploy container runtime on nodes of node_type."""
        logging.info(f"beginning container runtime deploy: "
                     f"node type: {node_type}, apt command: {apt_command}.")

        if apt_command == 'install':
            node_ips = self.get_nodes(node_type)
        elif apt_command == 'upgrade':
            nodes = self.get_nodes_from_cluster(node_type)
            node_ips = [x[1] for x in nodes]

        for node_ip in node_ips:
            logging.info(f"deploying container runtime to {node_ip}.")

            # https://kubernetes.io/docs/setup/production-environment/container-runtimes/
            self.scp_put_via_paramiko(
                f"{self.kubify_dirs['CHECKOUT_CONFIG_DIR']}/etc/modules-load.d/kubernetes.conf",
                self.config.get(node_type, 'remote_user'),
                node_ip,
                "/etc/modules-load.d/kubernetes.conf")

            self.run_command_via_ssh_paramiko(
                self.config.get(node_type, 'remote_user'),
                node_ip,
                'sudo modprobe overlay')

            self.run_command_via_ssh_paramiko(
                self.config.get(node_type, 'remote_user'),
                node_ip,
                'sudo modprobe br_netfilter')

            self.scp_put_via_paramiko(
                f"{self.kubify_dirs['CHECKOUT_CONFIG_DIR']}/etc/sysctl.d/99-kubernetes-cri.conf",
                self.config.get(node_type, 'remote_user'),
                node_ip,
                "/etc/sysctl.d/99-kubernetes-cri.conf")

            self.run_command_via_ssh_paramiko(
                self.config.get(node_type, 'remote_user'),
                node_ip,
                'sudo sysctl --system')

            # TODO: move this into ansible or up to common instructions to only run once?
            self.run_command_via_ssh_paramiko(
                self.config.get(node_type, 'remote_user'),
                node_ip,
                'sudo apt install -y apt-transport-https ca-certificates curl software-properties-common')

            self.deploy_containerd(
                node_ip,
                self.config.get(node_type, 'remote_user'),
                apt_command)

            logging.info(f"done deploying container runtime to {node_ip}.")
        logging.info(f"finished container runtime deploy.")

    @timeit
    def deploy_kubernetes_binaries(self, node_type):
        """deploy container runtime on nodes of node_type."""
        k8s_version = self.get_k8s_version()
        for node in self.get_nodes(node_type):
            logging.info(f"deploying kubernetes binaries to {node}.")

            full_code_version = self.get_k8s_full_code_version(
                self.config.get(node_type, 'remote_user'),
                node,
                k8s_version)

            self.run_command_via_ssh_paramiko(
                self.config.get(node_type, 'remote_user'),
                node,
                f"sudo apt-mark unhold kubeadm kubelet kubectl && "
                f"sudo apt install -y kubelet={full_code_version} kubadm={full_code_version} kubectl={full_code_version} nfs-common && "
                f"sudo apt-mark hold kubelet kubectl kubeadm")

            self.scp_put_via_paramiko(
                f"{self.kubify_dirs['CHECKOUT_CONFIG_DIR']}/etc/default/kubelet",
                self.config.get(node_type, 'remote_user'),
                node,
                "/etc/default/kubelet")

            self.run_command_via_ssh_paramiko(
                self.config.get(node_type, 'remote_user'),
                node,
                "sudo systemctl daemon-reload")

            self.run_command_via_ssh_paramiko(
                self.config.get(node_type, 'remote_user'),
                node,
                "sudo systemctl restart kubelet")

            self.run_command_via_ssh_paramiko(
                self.config.get(node_type, 'remote_user'),
                node,
                "sudo modprobe br_netfilter")

            self.run_command_via_ssh_paramiko(
                self.config.get(node_type, 'remote_user'),
                node,
                "sudo apt-mark hold kubelet kubeadm kubectl")

    @timeit
    def upgrade_kubernetes_binaries(self, node_type, specific_node=None):
        """upgrade kubernetes binaries on nodes of node_type."""
        k8s_version = self.get_k8s_version()

        for node_name, node_ip in self.get_nodes_from_cluster(node_type):
            logging.info(f"upgrading kubernetes binaries on {node_name} (ip: {node_ip}).")
            if specific_node and specific_node != node_ip:
                logging.info(f"This node ({node_ip}) does not match the specific one ({specific_node}) to upgrade. Skipping.")
                continue

            full_code_version = self.get_k8s_full_code_version(
                self.config.get(node_type, 'remote_user'),
                node_ip,
                k8s_version)

            self.run_command(
                f"{self.args.local_storage_dir}/kubectl "
                f"--kubeconfig={self.args.local_storage_dir}/admin.conf "
                f"drain {node_name} --ignore-daemonsets --delete-emptydir-data")

            self.run_command_via_ssh_paramiko(
                self.config.get(node_type, 'remote_user'),
                node_ip,
                f"sudo apt-mark unhold kubelet kubectl && "
                f"sudo apt install -y kubelet={full_code_version} kubectl={full_code_version} && "
                f"sudo apt-mark hold kubelet kubectl")

            self.deploy_containerd(node_ip, self.config.get(node_type, 'remote_user'), apt_command='upgrade')

            self.run_command_via_ssh_paramiko(
                self.config.get(node_type, 'remote_user'),
                node_ip,
                "sudo systemctl daemon-reload")

            self.run_command_via_ssh_paramiko(
                self.config.get(node_type, 'remote_user'),
                node_ip,
                "sudo systemctl restart kubelet")

            self.run_command(
                f"{self.args.local_storage_dir}/kubectl "
                f"--kubeconfig={self.args.local_storage_dir}/admin.conf "
                f"uncordon {node_name}")

    @timeit
    def run_command(self, cmd, return_output=False,
                    cmd_stdin=None, output_file='', ignore_errors=False, noop_command=False):
        """given a command, translate needed paths and run it.

           Args:
            noop_command: Command which makes no actual change to underlying system.
                          Expected to be safe to run even with dry_run.
        """
        command_list = cmd.split()
        output = ""

        if self.args.dry_run and not noop_command:
            logging.info(f"DRYRUN: Execute: {' '.join(command_list)}")
        else:
            try:
                logging.debug(f"running {' '.join(command_list)}")
                output = subprocess.check_output(command_list, stdin=cmd_stdin).decode()
                # TODO: Remove? This is super noisy.
                if output:
                    logging.debug(f"command output:\n{output}")
            except subprocess.CalledProcessError as err:
                logging.fatal(f"Error in running {command_list}.")
                logging.fatal(f"Output:\n{err.output.decode()}")
                output = err.output.decode()
                if ignore_errors:
                    logging.info('ERROR IGNORED, continuing on.')
                else:
                    sys.exit(1)

        if output_file:
            if self.args.dry_run:
                logging.debug(f"DRYRUN: writing output to {output_file}")
                return

            logging.debug(f"writing output to {output_file}")
            with open(output_file, 'w') as of:
                of.write(output)
            logging.debug(f"done writing output to {output_file}")

        if return_output:
            return output

    @timeit
    def initialize_control_plane(self):
        """initialize the kubernetes cluster control plane."""
        node_type = 'controller'
        kubeadm_join_command = ""
        kubeadm_certificate_key = ""
        initialized_first_node = False

        k8s_version = self.get_k8s_version()

        for node in self.get_nodes(node_type):
            logging.info(f"deploying control plane {node}.")

            if not initialized_first_node:
                # Only execute these commands if the first node has not been initialized yet.
                self.write_template(
                    f"{self.kubify_dirs['TEMPLATE_DIR']}/kubeadm-config.yaml",
                    f"{self.kubify_dirs['CHECKOUT_CONFIG_DIR']}/kubeadm-config.yaml",
                    {
                        'api_server_loadbalancer_hostport': self.config.get('general', 'api_server_loadbalancer_hostport'),
                        'cluster_name': self.config.get('general', 'cluster_name'),
                        'dns_domain': self.config.get('general', 'dns_domain'),
                        'kubernetes_version': f"{k8s_version.major}.{k8s_version.minor}.{k8s_version.micro}",
                        'pod_subnet': self.config.get('general', 'pod_subnet'),
                        'service_subnet': self.config.get('general', 'service_subnet'),
                    })

                self.scp_put_via_paramiko(
                    f"{self.kubify_dirs['CHECKOUT_CONFIG_DIR']}/kubeadm-config.yaml",
                    self.config.get('controller', 'remote_user'),
                    node,
                    '/tmp/kubeadm-config.yaml')

                kubeadm_init_command = (
                    f"sudo kubeadm init "
                    f"--config /tmp/kubeadm-config.yaml "
                    f"--upload-certs")

                if self.args.kubeadm_init_extra_flags:
                    kubeadm_init_command = f"{kubeadm_init_command} {self.args.kubeadm_init_extra_flags}"

                kubeadm_output = self.run_command_via_ssh_paramiko(
                    self.config.get(node_type, 'remote_user'),
                    node,
                    kubeadm_init_command,
                    return_output=True)

                if self.args.dry_run:
                    logging.info("DRYRUN: Parse kubeadm init output.")
                else:
                    self.join_token = RE_TOKEN.search(kubeadm_output).group(1)
                    self.discovery_token_ca_cert_hash = RE_DISCOVERY_TOKEN.search(kubeadm_output).group(1)
                    self.certificate_key = RE_CERTIFICATE_KEY.search(kubeadm_output).group(1)

                initialized_first_node = True

            else:
                self.run_command_via_ssh_paramiko(
                    self.config.get(node_type, 'remote_user'),
                    node,
                    f"sudo kubeadm join {self.config.get('general', 'api_server_loadbalancer_hostport')} "
                    f"--token {self.join_token} "
                    f"--discovery-token-ca-cert-hash {self.discovery_token_ca_cert_hash} "
                    f"--control-plane "
                    f"--certificate-key {self.certificate_key}")


    @timeit
    def join_worker_nodes(self):
        """join the worker nodes to the cluster."""
        for node in self.get_nodes('worker'):
            logging.info(f"adding worker node at {node}.")

            self.run_command_via_ssh(
                self.config.get('worker', 'remote_user'),
                node,
                f"sudo kubeadm join {self.config.get('general', 'api_server_loadbalancer_hostport')} "
                f"--token {self.join_token} "
                f"--discovery-token-ca-cert-hash {self.discovery_token_ca_cert_hash} ")

    @timeit
    def join_nodes(self, token, discovery_token, node_type, certificate_key=None):
        cp_flag = ""
        certificate_key_flag = ""
        for node in self.get_nodes(node_type):
            if node_type == "controller":
                cp_flag = "--control-plane"
                certificate_key_flag = f"--certificate-key {certificate_key}"

            logging.info(f"Adding node {node} of type {node_type}.")
            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                node,
                f"sudo kubeadm join {self.config.get('general', 'api_server_loadbalancer_hostport')} "
                f"--token {token} {cp_flag} {certificate_key_flag} "
                f"--discovery-token-ca-cert-hash {discovery_token}")

    @timeit
    def deploy_flannel(self):
        """deploy flannel to cluster."""
        logging.info(f"deploying flannel to kubernetes cluster.")
        # https://github.com/flannel-io/flannel
        self.run_command(
            f"{self.args.local_storage_dir}/kubectl apply "
            f"--kubeconfig={self.args.local_storage_dir}/admin.conf "
            f"-f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml")

    @timeit
    def store_configs_locally(self):
        """copy configs, certificates, etc to local directory if specified."""
        if not self.args.local_storage_dir:
            logging.info("No local storage directory specified.")
            return

        logging.info(f"Storing local data in {self.args.local_storage_dir}.")

        # Arbitrarily pick the first controller.
        hostname = self.get_nodes('controller')[0]

        self.run_command_via_ssh_paramiko(
            self.config.get('controller', 'remote_user'),
            hostname,
            f"sudo cp /etc/kubernetes/admin.conf /home/{self.config.get('controller', 'remote_user')}/")

        self.run_command_via_ssh_paramiko(
            self.config.get('controller', 'remote_user'),
            hostname,
            f"sudo chown {self.config.get('controller', 'remote_user')} "
            f"/home/{self.config.get('controller', 'remote_user')}/admin.conf ")

        if not os.path.exists(self.args.local_storage_dir):
            os.makedirs(self.args.local_storage_dir)

        if os.path.exists(f"{self.args.local_storage_dir}/admin.conf"):
            timestamp = f"{time.strftime('%Y%m%d-%H%M', time.localtime())}"
            timestamp_file = f"{self.args.local_storage_dir}/admin.conf.{timestamp}"
            logging.info(f"Moving old admin.conf to {timestamp_file}.")
            if self.args.dry_run:
                logging.info(f"DRYRUN: Would have moved admin.conf from {self.args.local_storage_dir}/admin.conf "
                             f"to {timestamp_file}.")
            else:
                os.rename(f"{self.args.local_storage_dir}/admin.conf",
                          f"{self.args.local_storage_dir}/admin.conf.{timestamp}")


        self.scp_get_via_paramiko(self.config.get('controller', 'remote_user'),
                                  hostname, 'admin.conf',
                                  f"{self.args.local_storage_dir}/admin.conf")

        self.scp_get_via_paramiko(self.config.get('controller', 'remote_user'),
                                  hostname, '/usr/bin/kubectl',
                                  f"{self.args.local_storage_dir}/kubectl")

    @timeit
    def get_kubeadm_join_tokens(self):
        """return kubeadm tokens for join command."""
        node_type = 'controller'
        for node in self.get_nodes(node_type, node_source="config"):
            logging.info(f"attempting to obtain join command from {node}.")
            token_create_output = self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                node,
                "sudo kubeadm token create --print-join-command",
                return_output=True)
            upload_certs_output = self.run_command_via_ssh_paramiko(
                self.config.get(node_type, 'remote_user'),
                node,
                "sudo kubeadm init phase upload-certs --upload-certs",
                return_output=True)
            if self.args.dry_run:
                logging.info(f"DRY RUN: Would have tried to parse tokens from {node}. Returning fake ones.")
                return "abcdefghijklmnopqrstuvwxyz", "0123456789", "09876543210"
            try:
                logging.info(f"Attempting to parse tokens from {node}.")
                token = RE_TOKEN.search(token_create_output).group(1)
                discovery_token_ca_cert_hash = RE_DISCOVERY_TOKEN.search(token_create_output).group(1)
                certificate_key = RE_CERTIFICATE_KEY_REINIT.search(upload_certs_output).group(1)
                logging.info(f"Successfully parsed tokens from {node}.")
                return certificate_key, token, discovery_token_ca_cert_hash
            except:
                logging.error(f"Unable to parse tokens from controller {node}. Trying next one.")
        logging.error(f"Unable to parse tokens from any controller nodes. Exiting")
        sys.exit(1)

    @timeit
    def build(self):
        """main build sequencer function."""

        logging.info(f"Executing kubify command: {self.args.command}")
        if self.args.command == 'install':
            self.update_apt_repos('controller')
            self.update_apt_repos('worker')
            self.deploy_container_runtime('controller', apt_command=self.args.command)
            self.deploy_container_runtime('worker', apt_command=self.args.command)
            self.deploy_kubernetes_binaries('controller')
            self.deploy_kubernetes_binaries('worker')
            self.initialize_control_plane()
            self.join_worker_nodes()
            self.store_configs_locally()
            self.reboot_hosts('controller')
            self.reboot_hosts('worker')
        elif self.args.command == 'upgrade':
            self.check_upgrade_viability(self.args.k8s_version)
            self.upgrade_control_plane(self.args.k8s_version)
            self.upgrade_kubernetes_binaries('controller')
            self.deploy_container_runtime('controller', apt_command=self.args.command)
            self.upgrade_worker_nodes()
            self.store_configs_locally()
        elif self.args.command == 'addnode':
            self.deploy_container_runtime('controller')
            self.deploy_container_runtime('worker')
            self.deploy_kubernetes_binaries('controller')
            self.deploy_kubernetes_binaries('worker')
            (cert_key, token, discovery_token) = self.get_kubeadm_join_tokens()
            self.join_nodes(token, discovery_token, 'controller', certificate_key=cert_key)
            self.join_nodes(token, discovery_token, 'worker')
            self.reboot_hosts('controller')
            self.reboot_hosts('worker')

def main():
    """main for Kubify script."""
    parser = argparse.ArgumentParser(
        description='Kubernetes cluster install/upgrade wrapper for kubeadm.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('command', type=str,
                        choices=['addnode','install','upgrade'],
                        help='kubify command to perform')
    parser.add_argument('--config',
                        required=True,
                        help='kubify config file.')
    parser.add_argument('--dry_run',
                        action='store_true',
                        help='dont actually do anything.')
    parser.add_argument('--debug',
                        action='store_true',
                        help='enable debug-level logging.')
    parser.add_argument('--k8s_version',
                        default='stable-1',
                        help='Kubernetes version to install. If no patch version provided, latest minor version used.')
    parser.add_argument('--kubeadm_init_extra_flags',
                        help='Additional flags to add to kubeadm init step.')
    parser.add_argument('--local_storage_dir',
                        help='Local on-disk directory to store configs, certificates, etc')
    parser.add_argument('--node',
                        action='append',
                        help='Add node to cluster. Form: {controller,worker}:hostname')

    args = parser.parse_args()

    if args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    logging.basicConfig(
        format='%(asctime)-10s %(filename)s:%(lineno)d %(levelname)s %(message)s',
        level=log_level)

    if args.config is None:
        logging.critical('required config file not defined. must be '
                         'with --config')
        sys.exit(1)

    if not os.path.exists(args.local_storage_dir):
        os.makedirs(args.local_storage_dir)

    start_time = time.time()
    try:
        k8s = KubeBuild(args)
        k8s.build()
        end_time = time.time()
        elapsed_time = end_time - start_time
        elapsed_time_strftime = time.strftime("%Hh:%Mm:%Ss", time.gmtime(elapsed_time))
        logging.info(f'completed running kubernetes build. Elapsed Time {elapsed_time_strftime}.')
    except:
        logging.error(f"Exception Caught: {traceback.print_exc()}")
        logging.error(f"args: {args}")
        logging.error(f"kubify_dirs: {k8s.kubify_dirs}")


if __name__ == '__main__':
    main()
