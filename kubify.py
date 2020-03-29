#!/usr/bin/env python3

import argparse
import base64
import configparser
import inspect
import logging
import os
import re
import shutil
import string
import subprocess
import sys
import time
import urllib.request
import yaml

import helpers

RE_VER = re.compile(r'^v?(?P<major>\d+)\.(?P<minor>\d+)\.?(?P<patch>\d+).*?$')

class KubeBuild(object):
    """define, create, and deploy a kubernetes cluster methods."""

    def __init__(self, cli_args):
        self.args = cli_args
        self.checkout_path = os.path.dirname(os.path.realpath(sys.argv[0]))

        self.config = configparser.ConfigParser()
        self.config.read(self.args.config)
        self.node_pod_cidrs = {}
        # Directories pertaining to checkout and output directory
        # configurations.
        self.kubify_dirs = {}
        self.set_k8s_paths()

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

    def get_node_domain(self):
        """return the node dns domain."""
        return self.config.get('general', 'domain_name')

    def get_node_ip_addresses(self, node_type):
        """get list of node IPs."""
        return self.config.get(node_type, 'ip_addresses')

    def get_node_count(self, node_type):
        """get number of nodes of a particular type."""
        return len(self.get_node_ip_addresses(node_type).split(','))

    def get_remote_k8s_version(self, version=None):
        """https://dl.k8s.io/release/stable-1.txt"""
        """if given a """
        if version is None:
            version = self.args.k8s_version
        f = urllib.request.urlopen(f"https://dl.k8s.io/release/{version}.txt")
        ver_string = f.read().decode().strip()
        # TODO: convert to string and strip newlines, etc.
        # Read it into a string?
        return ver_string

    def get_k8s_version(self, version=None):
        """parse the requested kubernetes version into."""
        if version is None:
            if (self.args.k8s_version.startswith('latest-') or
                self.args.k8s_version.startswith('stable-')):
                raw_version = self.get_remote_k8s_version()
            else:
                raw_version = self.args.k8s_version
        else:
            raw_version = version

        version = RE_VER.search(raw_version)
        if not version:
            logging.critical(f"Could not parse version from: {raw_version}")
            raise
        version_dict = version.groupdict()
        logging.info(f"parsed kubernetes version: {version_dict}.")
        if version_dict['patch'] is None:
            # If a patch version was not passed, set it to zero by default.
            version_dict['patch'] = 0
        logging.info(f"computed kubernetes version: {version_dict}")

        return version_dict

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
        ssh_args = "-q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
        self.run_command(
            f"scp {ssh_args} {local_path} "
            f"{remote_user}@{remote_host}:{remote_path}",
            ignore_errors=ignore_errors,
        )

    @timeit
    def run_command_via_ssh(self, remote_user, remote_host, command,
                            ignore_errors=False, return_output=False):
        """ssh to remote host and run specified command."""
        ssh_args = ('-o UserKnownHostsFile=/dev/null '
                    '-o StrictHostKeyChecking=no '
                    '-t -q')

        output = self.run_command(
            f"ssh {ssh_args} {remote_user}@{remote_host} {command}",
            ignore_errors=ignore_errors,
            return_output=return_output,
            )

        if return_output:
            return output

    @timeit
    def deploy_file(self, local_path, remote_user, remote_host, remote_path,
                    executable=False):
        """given local file(s) path, copy the file to a remote host and path."""

        bare_filenames = [os.path.basename(x) for x in local_path.split()]
        bare_filenames_str = " ".join(bare_filenames)
        self.scp_file(local_path, remote_user, remote_host, '~/')

        if executable:
            self.run_command_via_ssh(
                remote_user, remote_host,
                f"chmod +x {bare_filenames_str}")

        self.run_command_via_ssh(
            remote_user, remote_host,
            f"sudo cp {bare_filenames_str} {remote_path}")

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
        """given a disred k8s version, return true if we can upgrade to it."""
        logging.info(f"checking status of nodes to see if we can upgrade to {dest_k8s_ver}.")

        if self.args.dry_run:
            logging.info("DRY RUN: Would have parsed nodes yaml to get versions to make sure we can upgrade.")
            return

        kubectl_getnodes_output = self.run_command(
            f"{self.args.local_storage_dir}/kubectl "
            f"--kubeconfig={self.args.local_storage_dir}/admin.conf "
            "get nodes -o yaml",
            return_output=True)
        nodes_yaml = yaml.safe_load(kubectl_getnodes_output)
        node_versions = []
        for cur_node in nodes_yaml['items']:
            node_name = cur_node['metadata']['labels']['kubernetes.io/hostname']
            node_ver = cur_node['status']['nodeInfo']['kubeletVersion']
            node_versions.append(node_ver)
            logging.info(f"Found node {node_name} running kubelet version {node_ver}.")
        node_versions = set(node_versions)
        dest_k8s_ver = self.get_k8s_version()

        # TODO: add logic to bail when there are nodes of two different minor versions.
        # this is an un-upgradable scenario because one could be skipping a minor version.
        for c in node_versions:
            c_ver = RE_VER.search(c)
            logging.debug(f"current node version: {c_ver.groupdict()}")
            if c_ver is None:
                logging.fatal(f'unable to determine node version dictionary: {c}')
            if dest_k8s_ver['major'] != c_ver['major']:
                logging.fatal(f'attempting an upgrade across major versions. not supported yet. '
                              f'destination: {dest_k8s_ver}, found: {c}')
            minor_ver_diff = int(dest_k8s_ver['minor']) - int(c_ver['minor'])
            if minor_ver_diff > 1:
                logging.exception('attempting to skip minor version upgrade. currently unsupported by kubeadm.')
                raise
        return True

    @timeit
    def upgrade_nodes(self, node_type):
        """upgrade a set of nodes to the new kubernetes version."""
        k8s_version_dict = self.get_k8s_version()
        k8s_version = f"{k8s_version_dict['major']}.{k8s_version_dict['minor']}.{k8s_version_dict['patch']}"

        for node in self.get_nodes(node_type):
            logging.info(f"upgrading kubernetes node {node} to {self.get_k8s_version()}.")
            # TODO: make figuring out the hostname of a node correct.
            # if it's using fqdn, we should use it.
            # should we get node names from kubectl get nodes output?
            node_shortname = node.split('.')[0]

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                node,
                f"sudo apt-mark unhold kubeadm && "
                f"sudo apt update && "
                f"sudo apt install -y kubeadm={k8s_version}-00 && "
                f"sudo apt-mark hold kubeadm")

            self.run_command(
                f"{self.args.local_storage_dir}/kubectl "
                f"--kubeconfig={self.args.local_storage_dir}/admin.conf "
                f"drain {node_shortname} --ignore-daemonsets --delete-local-data")

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                node,
                f"sudo kubeadm upgrade node")

            self.upgrade_kubernetes_binaries(node_type, specific_node=node)

            self.run_command(
                f"{self.args.local_storage_dir}/kubectl "
                f"--kubeconfig={self.args.local_storage_dir}/admin.conf "
                f"uncordon {node_shortname}")

    @timeit
    def upgrade_control_plane(self, k8s_ver):
        """upgrade k8s control plane to new k8s version."""
        first_node_done=False
        node_type='controller'
        k8s_ver_dict = self.get_k8s_version()
        ver = f"{k8s_ver_dict['major']}.{k8s_ver_dict['minor']}.{k8s_ver_dict['patch']}"

        for node in self.get_nodes(node_type):
            # TODO: make figuring out the hostname of a node correct.
            # if it's using fqdn, we should use it.
            # should we get node names from kubectl get nodes output?
            node_shortname = node.split('.')[0]

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                node,
                f"sudo apt-mark unhold kubeadm && "
                f"sudo apt update && "
                f"sudo apt install -y kubeadm={ver}-00 && "
                f"sudo apt-mark hold kubeadm")

            remote_k8s_version = self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                node,
                "kubeadm version -o yaml",
                return_output = True)

            if self.args.dry_run:
                logging.info("DRY RUN: Would have retrieved remote kubeadm version.")
                logging.info("DRY RUN: Would have checked that remote kubeadm version matched what we expected.")
            else:
                remote_version_yaml = yaml.safe_load(remote_k8s_version)
                remote_version_dict = self.get_k8s_version(
                    remote_version_yaml['clientVersion']['gitVersion'])
                if k8s_ver_dict != remote_version_dict:
                    logging.fatal(f"Installed kubeadm version mismatch. "
                                    f"Expected: {k8s_ver_dict}. Found: {remote_version_dict}.")

            self.run_command(
                f"{self.args.local_storage_dir}/kubectl "
                f"--kubeconfig={self.args.local_storage_dir}/admin.conf "
                f"drain {node_shortname} --ignore-daemonsets --delete-local-data")

            if first_node_done is False:
                self.run_command_via_ssh(
                    self.config.get(node_type, 'remote_user'),
                    node,
                    'sudo kubeadm upgrade plan')

                self.run_command_via_ssh(
                    self.config.get(node_type, 'remote_user'),
                    node,
                    f"sudo kubeadm upgrade apply --yes v{ver}")
                first_node_done = True
            else:
                self.run_command_via_ssh(
                    self.config.get(node_type, 'remote_user'),
                    node,
                    f"sudo kubeadm upgrade node")

            self.run_command(
                f"{self.args.local_storage_dir}/kubectl "
                f"--kubeconfig={self.args.local_storage_dir}/admin.conf "
                f"uncordon {node_shortname}")
        logging.info("finished upgrade_control_plane")

    @timeit
    def get_nodes(self, node_type):
        """given a node type, return a list of hosts of that node type."""
        nodes = []
        for node_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                self.config.get(node_type, 'prefix'),
                self.get_node_domain(),
                node_index)
            nodes.append(hostname)
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
    def deploy_container_runtime(self, node_type, apt_command='install'):
        """deploy container runtime on nodes of node_type."""
        k8s_version = self.get_k8s_version()
        logging.info(f"beginning container runtime deploy: "
                     f"node type: {node_type}, apt command: {apt_command}.")
        for node in self.get_nodes(node_type):
            logging.info(f"deploying container runtime to {node}.")

            self.deploy_file(
                f"{self.kubify_dirs['CHECKOUT_CONFIG_DIR']}/etc/sysctl.d/99-kubernetes-cri.conf",
                self.config.get(node_type, 'remote_user'),
                node,
                "/etc/sysctl.d/99-kubernetes-cri.conf")

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                node,
                'sudo sysctl --system')

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                node,
                'sudo apt install -y apt-transport-https ca-certificates curl software-properties-common')

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                node,
                'sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -')

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                node,
                'sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"')

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                node,
                f'sudo apt update && sudo apt {apt_command} -y containerd.io')

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                node,
                'sudo mkdir -p /etc/containerd')

            self.deploy_file(
                f"{self.kubify_dirs['CHECKOUT_CONFIG_DIR']}/etc/containerd/config.toml",
                self.config.get(node_type, 'remote_user'),
                node,
                "/etc/containerd/config.toml")

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                node,
                'sudo systemctl enable containerd')

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                node,
                'sudo systemctl restart containerd')

    @timeit
    def deploy_kubernetes_binaries(self, node_type):
        """deploy container runtime on nodes of node_type."""
        k8s_version_dict = self.get_k8s_version()
        k8s_version = f"{k8s_version_dict['major']}.{k8s_version_dict['minor']}.{k8s_version_dict['patch']}"

        for node in self.get_nodes(node_type):
            logging.info(f"deploying kubernetes binaries to {node}.")

            self.deploy_file(
                f"{self.kubify_dirs['CHECKOUT_CONFIG_DIR']}/etc/apt/sources.list.d/kubernetes.list",
                self.config.get(node_type, 'remote_user'),
                node,
                "/etc/apt/sources.list.d/kubernetes.list")

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                node,
                'sudo curl -o /tmp/packages.cloud.google.com-apt-key.gpg -s https://packages.cloud.google.com/apt/doc/apt-key.gpg')

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                node,
                "sudo apt-key add /tmp/packages.cloud.google.com-apt-key.gpg")

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                node,
                "sudo apt update")

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                node,
                f"sudo apt install -y kubelet={k8s_version}-00 kubeadm={k8s_version}-00 kubectl={k8s_version}-00 nfs-common")

            self.deploy_file(
                f"{self.kubify_dirs['CHECKOUT_CONFIG_DIR']}/etc/default/kubelet",
                self.config.get(node_type, 'remote_user'),
                node,
                "/etc/default/kubelet")

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                node,
                "sudo systemctl daemon-reload")

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                node,
                "sudo systemctl restart kubelet")

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                node,
                "sudo apt-mark hold kubelet kubeadm kubectl")

    @timeit
    def upgrade_kubernetes_binaries(self, node_type, specific_node=None):
        """upgrade kubernetes binaries on nodes of node_type."""
        k8s_version_dict = self.get_k8s_version()
        k8s_version = f"{k8s_version_dict['major']}.{k8s_version_dict['minor']}.{k8s_version_dict['patch']}"

        for node in self.get_nodes(node_type):
            logging.info(f"upgrading kubernetes binaries to {node}.")
            if specific_node is None:
                pass
            elif specific_node != node:
                logging.info(f"Only upgrading specific node: {node}. Skipping.")
                continue

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                node,
                f"sudo apt-mark unhold kubelet kubectl && "
                f"sudo apt update && "
                f"sudo apt install -y kubelet={k8s_version}-00 kubectl={k8s_version}-00 && "
                f"sudo apt-mark hold kubelet kubectl")

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                node,
                "sudo systemctl restart kubelet")

    @timeit
    def run_command(self, cmd, return_output=False,
                    cmd_stdin=None, output_file='', ignore_errors=False):
        """given a command, translate needed paths and run it."""
        command_list = cmd.split()
        output = ""

        if self.args.dry_run:
            logging.info(f"DRYRUN: Execute: {' '.join(command_list)}")
        else:
            try:
                logging.debug(f"running {' '.join(command_list)}")
                output = subprocess.check_output(command_list, stdin=cmd_stdin).decode()
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
                        'service_subnet': self.config.get('general', 'service_subnet'),
                        'pod_subnet': self.config.get('general', 'pod_subnet'),
                        'kubernetes_version': f"{k8s_version['major']}.{k8s_version['minor']}.{k8s_version['patch']}",
                    })

                self.deploy_file(
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

                kubeadm_output = self.run_command_via_ssh(
                    self.config.get(node_type, 'remote_user'),
                    node,
                    kubeadm_init_command,
                    return_output=True)

                if self.args.dry_run:
                    logging.info("DRYRUN: Parse kubeadm init output.")
                else:
                    RE_TOKEN = re.compile(r'--token (\S+)', re.MULTILINE)
                    RE_DISCOVERY_TOKEN = re.compile(r'--discovery-token-ca-cert-hash (\S+)')
                    RE_CERTIFICATE_KEY = re.compile(r'--certificate-key (\S+)')

                    self.join_token = RE_TOKEN.search(kubeadm_output).group(1)
                    self.discovery_token_ca_cert_hash = RE_DISCOVERY_TOKEN.search(kubeadm_output).group(1)
                    self.certificate_key = RE_CERTIFICATE_KEY.search(kubeadm_output).group(1)

                initialized_first_node = True

            else:
                self.run_command_via_ssh(
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
    def deploy_flannel(self):
        """deploy flannel to cluster."""
        logging.info(f"deploying flanel to kubernetes cluster.")
        self.run_command(
            f"{self.args.local_storage_dir}/kubectl apply "
            f"--kubeconfig={self.args.local_storage_dir}/admin.conf "
            f"-f https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml")

    @timeit
    def store_configs_locally(self):
        """copy configs, certificates, etc to local directory if specified."""
        if not self.args.local_storage_dir:
            logging.info("No local storage directory specified.")
            return

        logging.info(f"Storing local data in {self.args.local_storage_dir}.")

        hostname = helpers.hostname_with_index(
            self.config.get('controller', 'prefix'),
            self.get_node_domain(),
            0)

        self.run_command_via_ssh(
            self.config.get('controller', 'remote_user'),
            hostname,
            f"sudo cp /etc/kubernetes/admin.conf /home/{self.config.get('controller', 'remote_user')}/")

        self.run_command_via_ssh(
            self.config.get('controller', 'remote_user'),
            hostname,
            f"sudo chown {self.config.get('controller', 'remote_user')} "
            f"/home/{self.config.get('controller', 'remote_user')}/admin.conf ")

        if not os.path.exists(self.args.local_storage_dir):
            os.makedirs(self.args.local_storage_dir)

        self.run_command(
            f"scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "
            f"{self.config.get('controller', 'remote_user')}@{hostname}:~/admin.conf "
            f"{self.args.local_storage_dir}/admin.conf")

        self.run_command(
            f"scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "
            f"{self.config.get('controller', 'remote_user')}@{hostname}:/usr/bin/kubectl "
            f"{self.args.local_storage_dir}/kubectl")

    @timeit
    def build(self):
        """main build sequencer function."""

        logging.info(f"Executing kubify command: {self.args.command}")
        if self.args.command == 'install':
            self.deploy_container_runtime('controller')
            self.deploy_container_runtime('worker')
            self.deploy_kubernetes_binaries('controller')
            self.deploy_kubernetes_binaries('worker')
            self.initialize_control_plane()
            self.join_worker_nodes()
            self.store_configs_locally()
            self.deploy_flannel()
            self.reboot_hosts('controller')
            self.reboot_hosts('worker')
        elif self.args.command == 'upgrade':
            self.check_upgrade_viability(self.args.k8s_version)
            self.upgrade_control_plane(self.args.k8s_version)
            self.deploy_container_runtime('controller', apt_command='upgrade')
            self.upgrade_kubernetes_binaries('controller')
            self.deploy_flannel()
            self.upgrade_nodes('worker')
            self.deploy_container_runtime('worker', apt_command='upgrade')
            self.store_configs_locally()

def main():
    """main for Kubify script."""
    parser = argparse.ArgumentParser(
        description='Kubernetes cluster install/upgrade wrapper for kubeadm.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('command', type=str,
                        choices=['install','upgrade'],
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
                        help='Kubernetes version to install.')
    parser.add_argument('--kubeadm_init_extra_flags',
                        help='Additional flags to add to kubeadm init step.')
    parser.add_argument('--local_storage_dir',
                        help='Local on-disk directory to store configs, certificates, etc')

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
        logging.error("Exception Caught")
        logging.error(f"args: {args}")
        logging.error(f"kubify_dirs: {k8s.kubify_dirs}")


if __name__ == '__main__':
    main()
