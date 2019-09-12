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
import urllib.request, urllib.parse, urllib.error

import helpers



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
            logging.info(f"DRYRUN: would have written template "
                         f"{input_template} to {output_path}")
        else:
            with open(output_path, 'w') as output_file:
                output_file.write(output)


    @timeit
    def build(self):
        """main build sequencer function."""

        self.deploy_container_runtime('controller')
        self.deploy_container_runtime('worker')
        self.deploy_kubernetes_binaries('controller')
        self.deploy_kubernetes_binaries('worker')
        self.initialize_control_plane()
        self.join_worker_nodes()

        self.deploy_kuberouter()
        self.store_configs_locally()

    @timeit
    def deploy_container_runtime(self, node_type):
        """deploy container runtime on nodes of node_type."""
        nodes = self.config.get(node_type, 'ip_addresses').split(',')
        for node_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                self.config.get(node_type, 'prefix'),
                self.get_node_domain(),
                node_index)
            logging.info(f"deploying container runtime to {hostname}.")

            self.deploy_file(
                f"{self.kubify_dirs['CHECKOUT_CONFIG_DIR']}/etc/sysctl.d/99-kubernetes-cri.conf",
                self.config.get(node_type, 'remote_user'),
                nodes[node_index],
                "/etc/sysctl.d/99-kubernetes-cri.conf")

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                nodes[node_index],
                'sudo sysctl --system')

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                nodes[node_index],
                'sudo apt install -y software-properties-common')

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                nodes[node_index],
                'sudo add-apt-repository -y ppa:projectatomic/ppa',
                ignore_errors=True)

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                nodes[node_index],
                'sudo apt install -y cri-o-1.13')

            self.deploy_file(
                f"{self.kubify_dirs['CHECKOUT_CONFIG_DIR']}/etc/crio/crio.conf",
                self.config.get(node_type, 'remote_user'),
                nodes[node_index],
                "/etc/crio/crio.conf")

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                nodes[node_index],
                'sudo systemctl restart crio')

    @timeit
    def deploy_kubernetes_binaries(self, node_type):
        """deploy container runtime on nodes of node_type."""
        nodes = self.config.get(node_type, 'ip_addresses').split(',')
        for node_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                self.config.get(node_type, 'prefix'),
                self.get_node_domain(),
                node_index)
            logging.info(f"deploying kubernetes binaries to {hostname}.")

            self.deploy_file(
                f"{self.kubify_dirs['CHECKOUT_CONFIG_DIR']}/etc/apt/sources.list.d/kubernetes.list",
                self.config.get(node_type, 'remote_user'),
                nodes[node_index],
                "/etc/apt/sources.list.d/kubernetes.list")

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                nodes[node_index],
                'sudo curl -o /tmp/packages.cloud.google.com-apt-key.gpg -s https://packages.cloud.google.com/apt/doc/apt-key.gpg')

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                nodes[node_index],
                "sudo apt-key add /tmp/packages.cloud.google.com-apt-key.gpg")

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                nodes[node_index],
                "sudo apt update")

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                nodes[node_index],
                "sudo apt install -y kubelet kubeadm kubectl")

            self.deploy_file(
                f"{self.kubify_dirs['CHECKOUT_CONFIG_DIR']}/etc/default/kubelet",
                self.config.get(node_type, 'remote_user'),
                nodes[node_index],
                "/etc/default/kubelet")

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                nodes[node_index],
                "sudo systemctl daemon-reload")

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                nodes[node_index],
                "sudo systemctl restart kubelet")

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                nodes[node_index],
                "sudo apt-mark hold kubelet kubeadm kubectl")


    @timeit
    def run_command(self, cmd, return_output=False,
                    cmd_stdin=None, output_file='', ignore_errors=False):
        """given a command, translate needed paths and run it."""
        command_list = cmd.split()
        output = ""

        if self.args.dry_run:
            logging.info(f"DRYRUN: would have run {' '.join(command_list)}")
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
        nodes = self.config.get(node_type, 'ip_addresses').split(',')
        kubeadm_join_command = ""
        kubeadm_certificate_key = ""


        for node_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                self.config.get(node_type, 'prefix'),
                self.get_node_domain(),
                node_index)   
            logging.info(f"deploying control plane {hostname}.")

            if node_index == 0:

                self.write_template(
                    f"{self.kubify_dirs['TEMPLATE_DIR']}/kubeadm-config.yaml",
                    f"{self.kubify_dirs['CHECKOUT_CONFIG_DIR']}/kubeadm-config.yaml",
                    {
                        'api_server_loadbalancer_hostport': self.config.get('general', 'api_server_loadbalancer_hostport'),
                        'service_subnet': self.config.get('general', 'service_subnet'),
                        'pod_subnet': self.config.get('general', 'pod_subnet'),
                    })

                self.deploy_file(
                    f"{self.kubify_dirs['CHECKOUT_CONFIG_DIR']}/kubeadm-config.yaml",
                    self.config.get('controller', 'remote_user'),
                    hostname,
                    '/tmp/kubeadm-config.yaml')

                kubeadm_init_command = (
                    f"sudo kubeadm init "
                    f"--config /tmp/kubeadm-config.yaml "
                    f"--upload-certs")

                if self.args.kubeadm_init_extra_flags:
                    kubeadm_init_command = f"{kubeadm_init_command} {self.args.kubeadm_init_extra_flags}"

                kubeadm_output = self.run_command_via_ssh(
                    self.config.get(node_type, 'remote_user'),
                    hostname,
                    kubeadm_init_command,
                    return_output=True)

                RE_TOKEN = re.compile(r'--token (\S+)', re.MULTILINE)
                RE_DISCOVERY_TOKEN = re.compile(r'--discovery-token-ca-cert-hash (\S+)')
                RE_CERTIFICATE_KEY = re.compile(r'--certificate-key (\S+)')

                self.join_token = RE_TOKEN.search(kubeadm_output).group(1)
                self.discovery_token_ca_cert_hash = RE_DISCOVERY_TOKEN.search(kubeadm_output).group(1)
                self.certificate_key = RE_CERTIFICATE_KEY.search(kubeadm_output).group(1)


            else:
                self.run_command_via_ssh(
                    self.config.get(node_type, 'remote_user'),
                    hostname,
                    f"sudo kubeadm join {self.config.get('general', 'api_server_loadbalancer_hostport')} "
                    f"--token {self.join_token} "
                    f"--discovery-token-ca-cert-hash {self.discovery_token_ca_cert_hash} "
                    f"--control-plane "
                    f"--certificate-key {self.certificate_key}")


    @timeit
    def join_worker_nodes(self):
        """join the worker nodes to the cluster."""
        node_type = 'worker'
        nodes = self.config.get(node_type, 'ip_addresses').split(',')

        for node_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                self.config.get(node_type, 'prefix'),
                self.get_node_domain(),
                node_index)
            logging.info(f"adding worker node at {hostname}.")

            self.run_command_via_ssh(
                self.config.get(node_type, 'remote_user'),
                hostname,
                f"sudo kubeadm join {self.config.get('general', 'api_server_loadbalancer_hostport')} "
                f"--token {self.join_token} "
                f"--discovery-token-ca-cert-hash {self.discovery_token_ca_cert_hash} ")

    @timeit
    def deploy_kuberouter(self):
        """deploy kuberouter to cluster."""
        node_type = 'controller'
        nodes = self.config.get(node_type, 'ip_addresses').split(',')
        hostname = helpers.hostname_with_index(
            self.config.get('controller', 'prefix'),
            self.get_node_domain(),
            # for right now, only operate on host 0 in the index.
            0)

        logging.info(f"deploying kuberouter to kubernetes cluster via host {hostname}.")
        self.run_command_via_ssh(
            self.config.get(node_type, 'remote_user'),
            hostname,
            "sudo kubectl apply --kubeconfig /etc/kubernetes/admin.conf "
            "-f https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/daemonset/kubeadm-kuberouter.yaml")

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


def main():
    """main for Kubify script."""
    parser = argparse.ArgumentParser(
        description='Install Kubernetes cluster with kubeadm',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--config',
                        required=True,
                        help='kubify config file.')
    parser.add_argument('--dry_run',
                        action='store_true',
                        help='dont actually do anything.')
    parser.add_argument('--debug',
                        action='store_true',
                        help='enable debug-level logging.')
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

    start_time = time.time()
    try:
        k8s = KubeBuild(args)
        k8s.build()
    except:
        logging.error("Exception Caught")
        logging.error(f"args: {args}")
        logging.error(f"kubify_dirs: {k8s.kubify_dirs}")
        raise
    end_time = time.time()
    elapsed_time = end_time - start_time
    elapsed_time_strftime = time.strftime("%Hh:%Mm:%Ss", time.gmtime(elapsed_time))
    logging.info(f'completed running kubernetes build. Elapsed Time {elapsed_time_strftime}.')


if __name__ == '__main__':
    main()
