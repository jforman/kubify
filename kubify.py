#!/usr/bin/env python3

import argparse
import base64
import configparser
import json
import logging
import os
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
        self.kube_release_dir = (f'https://storage.googleapis.com/'
                                 f'kubernetes-release/release/v{self.args.kube_ver}'
                                 f'/bin/linux/amd64')

        self.config = configparser.ConfigParser()
        self.config.read(self.args.config)
        self.node_pod_cidrs = {}
        # Directories pertaining to checkout and output directory
        # configurations.
        self.kubify_dirs = {}
        self.set_k8s_paths()

        logging.debug(f'Checkout Path: {self.checkout_path}, Output Dir: {self.args.output_dir}')

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

    def get_etcd_discovery_url(self, cluster_size):
        """get the etcd discovery url for cluster size."""
        logging.info(f"Requesting new etcd discover URL. Cluster size: {cluster_size}.")
        f = urllib.request.urlopen(f"https://discovery.etcd.io/new?size={cluster_size}")
        disc_url = f.read().decode()
        logging.info(f"Retrieved discovery URL: {disc_url}")
        return disc_url

    def get_node_ip_addresses(self, node_type):
        """get list of node IPs."""
        return self.config.get(node_type, 'ip_addresses')

    def get_node_count(self, node_type):
        """get number of nodes of a particular type."""
        return len(self.get_node_ip_addresses(node_type).split(','))

    def set_node_pod_cidrs(self):
        """create dictionary of node->pod CIDR mappings."""
        node_output = self.run_command(
            (f"{self.kubify_dirs['BIN_DIR']}/kubectl "
             f"--kubeconfig {self.kubify_dirs['ADMIN_DIR']}/admin.kubeconfig "
             "get nodes -o json"),
            return_output=True)
        logging.debug(f"node_output: {node_output}")
        if self.args.dry_run:
            logging.info("DRY RUN: No node CIDRs to process.")
            return
        node_json = json.loads(node_output)
        for item in node_json["items"]:
            node = item["metadata"]["name"]
            podcidr = item["spec"]["podCIDR"]
            self.node_pod_cidrs[node] = podcidr
            logging.info(f"Node {node} has pod CIDR {podcidr}.")

    @timeit
    def set_k8s_paths(self):
        """given string containing special macro, return command line with
        directories substituted in string."""

        self.kubify_dirs['CHECKOUT_DIR'] = os.path.dirname(os.path.realpath(sys.argv[0]))
        self.kubify_dirs['OUTPUT_DIR'] =  self.args.output_dir

        self.kubify_dirs['ADDON_DIR'] = os.path.join(
            self.kubify_dirs['OUTPUT_DIR'], 'addon')
        self.kubify_dirs['ADMIN_DIR'] = os.path.join(
            self.kubify_dirs['OUTPUT_DIR'], 'admin')

        self.kubify_dirs['API_SERVER_DIR'] = os.path.join(
            self.kubify_dirs['OUTPUT_DIR'], 'api_server')

        self.kubify_dirs['BIN_DIR'] = os.path.join(
                self.kubify_dirs['OUTPUT_DIR'],
                'bin', self.args.kube_ver)

        self.kubify_dirs['CA_DIR'] = os.path.join(
            self.kubify_dirs['OUTPUT_DIR'], 'ca')
        self.kubify_dirs['CHECKOUT_CONFIG_DIR'] = os.path.join(
            self.kubify_dirs['CHECKOUT_DIR'], 'configs')

        self.kubify_dirs['ENCRYPTION_DIR'] = os.path.join(
            self.kubify_dirs['OUTPUT_DIR'],
            'encryption')

        self.kubify_dirs['INSTALL_DIR'] = self.config.get('general', 'install_dir')

        self.kubify_dirs['ETCD_DIR'] = os.path.join(
            self.kubify_dirs['OUTPUT_DIR'], 'etcd')
        self.kubify_dirs['PROXY_DIR'] = os.path.join(
            self.kubify_dirs['OUTPUT_DIR'], 'proxy')

        self.kubify_dirs['CHECKOUT_SCRIPTS_DIR'] =  os.path.join(
            self.kubify_dirs['CHECKOUT_DIR'], 'scripts')

        self.kubify_dirs['TEMPLATE_DIR'] =  os.path.join(
            self.kubify_dirs['CHECKOUT_DIR'], 'templates')
        self.kubify_dirs['TMP_DIR'] = os.path.join(
            self.kubify_dirs['OUTPUT_DIR'], 'tmp')
        self.kubify_dirs['WORKER_DIR'] = os.path.join(
            self.kubify_dirs['OUTPUT_DIR'], 'workers')

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
        self.create_output_dirs()

        if not self.args.skip_tools_download:
            self.download_tools()

        if not self.args.action:
            return

        if 'create_certs' in self.args.action:
            self.create_ca_cert_private_key()
            self.create_etcd_certs('controller')
            self.create_etcd_certs('worker')
            self.create_kubelet_certs('controller')
            self.create_kubelet_certs('worker')
            self.create_admin_client_cert()
            self.create_kube_controller_manager_cert()
            self.create_kube_proxy_certs()
            self.create_kube_scheduler_certs()
            self.create_api_server_cert()
            self.create_kube_service_account_certs()

        if 'create_configs' in self.args.action:
            self.create_kubelet_kubeconfigs('controller')
            self.create_kubelet_kubeconfigs('worker')
            self.create_kubeproxy_configs()
            self.create_kubecontrollermanager_kubeconfig()
            self.create_kubescheduler_kubeconfig()
            self.create_admin_kubeconfig()
            self.create_encryption_configs()
            self.create_etcd_configs('controller')
            self.create_etcd_configs('worker')
            self.create_control_plane_configs()
            self.create_containerd_configs()
            self.create_kubelet_configs('controller')
            self.create_kubelet_configs('worker')
            self.create_coredns_config()

        if 'deploy' in self.args.action:
            self.deploy_etcd('controller')
            self.deploy_etcd('worker')
            self.deploy_control_plane()
            self.deploy_control_plane_rbac()
            self.deploy_kubelet('controller')
            self.deploy_kubelet('worker')
            self.deploy_containerd('controller')
            self.deploy_containerd('worker')

            # We have to deploy the kubelets first
            # before we can determine the POD CIDR
            # for each node.
            self.set_node_pod_cidrs()
            self.create_cni_configs('controller')
            self.create_cni_configs('worker')
            self.deploy_cni_configs('controller')
            self.deploy_cni_configs('worker')

            self.deploy_kubeproxy('controller')
            self.deploy_kubeproxy('worker')
            self.apply_taints_and_labels('controller')

            # Deploy Pod Security Policies and roles
            self.deploy_pod_security_policies()

            # Deploy pods critical to Kubernetes cluster operation.
            self.deploy_kuberouter()
            self.deploy_coredns()

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
                    logging.debug(f"command output: {output}")
            except subprocess.CalledProcessError as err:
                logging.fatal(f"Error in running {command_list}. Output: {err.output}")
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
    def create_output_dirs(self):
        """create the directory structure for storing create files."""
        subdirs = ['', 'addon', 'addon/dashboard', 'admin', 'api_server',
                   'bin', 'ca', 'encryption', 'etcd', 'proxy', 'tmp', 'workers']
        if self.args.clear_output_dir:
            if self.args.dry_run:
                logging.info(f"DRYRUN: Would have deleted {self.args.output_dir}")
            else:
                logging.info(f"Deleting directory {self.args.output_dir}")
                if os.path.exists(self.args.output_dir):
                    shutil.rmtree(self.args.output_dir)

        for current_dir in subdirs:
            if self.args.dry_run:
                logging.debug(f"DRYRUN: create directory {os.path.join(self.args.output_dir,current_dir)}")
            else:
                dest_dir = os.path.join(self.args.output_dir,current_dir)
                if not os.path.exists(dest_dir):
                    logging.debug(f"Creating directory {dest_dir}.")
                    os.makedirs(dest_dir)

    @timeit
    def download_tools(self):
        """download kubernetes cluster and cfssl cert creation binaries."""
        etcd_version = self.config.get('general', 'etcd_version')
        files_to_get = {
            'https://pkg.cfssl.org/R1.2/cfssl_linux-amd64':
            f"{self.kubify_dirs['BIN_DIR']}/cfssl",

            'https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64':
            f"{self.kubify_dirs['BIN_DIR']}/cfssljson",

            os.path.join(self.kube_release_dir, 'kubectl'):
            f"{self.kubify_dirs['BIN_DIR']}/kubectl",
            os.path.join(self.kube_release_dir, 'kubelet'):
            f"{self.kubify_dirs['BIN_DIR']}/kubelet",
            os.path.join(self.kube_release_dir, 'kube-apiserver'):
            f"{self.kubify_dirs['BIN_DIR']}/kube-apiserver",
            os.path.join(self.kube_release_dir, 'kube-controller-manager'):
            f"{self.kubify_dirs['BIN_DIR']}/kube-controller-manager",
            os.path.join(self.kube_release_dir, 'kube-proxy'):
            f"{self.kubify_dirs['BIN_DIR']}/kube-proxy",
            os.path.join(self.kube_release_dir, 'kube-scheduler'):
            f"{self.kubify_dirs['BIN_DIR']}/kube-scheduler",
            f"https://github.com/etcd-io/etcd/releases/download/v{etcd_version}/etcd-v{etcd_version}-linux-amd64.tar.gz":
            f"{self.kubify_dirs['BIN_DIR']}/etcd-v{etcd_version}.tar.gz"
        }

        if not os.path.exists(f"{self.kubify_dirs['BIN_DIR']}"):
            os.makedirs(f"{self.kubify_dirs['BIN_DIR']}")

        logging.info("downloading new set of binary tools")
        for remotef, localf in files_to_get.items():
            if self.args.dry_run:
                logging.info(f"DRY RUN: would have downloaded {remotef} to {localf}.")
                continue

            logging.debug(f"downloading {remotef} to {localf}")
            urllib.request.urlretrieve(remotef, localf)
            os.chmod(localf, 0o775)

        self.run_command(f"tar -xvzf {self.kubify_dirs['BIN_DIR']}/etcd-v{etcd_version}.tar.gz -C {self.kubify_dirs['BIN_DIR']}")
        logging.info("done downloading tools")

    @timeit
    def create_control_plane_configs(self):
        node_type = 'controller'
        nodes = self.config.get(node_type, 'ip_addresses').split(',')
        etcd_servers = ",".join([f"https://{x}:2379" for x in nodes])
        template_vars = {
            'CERTS_DIR': self.config.get('general',
                                         'ssl_certs_dir'),
            'CLUSTER_NAME': self.config.get('general',
                                            'cluster_name'),
            'CLUSTER_CIDR': self.config.get('general',
                                            'cluster_cidr'),
            'ETCD_SERVERS': etcd_servers,
            'INSTALL_DIR': self.config.get('general',
                                           'install_dir'),
            'SERVICE_CIDR': self.config.get('general',
                                            'service_cidr')}

        self.write_template(
            f"{self.kubify_dirs['TEMPLATE_DIR']}/kube-controller-manager.service",
            f"{self.kubify_dirs['API_SERVER_DIR']}/kube-controller-manager.service",
            template_vars)

        self.write_template(
            f"{self.kubify_dirs['TEMPLATE_DIR']}/kube-scheduler.service",
            f"{self.kubify_dirs['API_SERVER_DIR']}/kube-scheduler.service",
            template_vars)

        self.write_template(
            f"{self.kubify_dirs['TEMPLATE_DIR']}/kube-scheduler.yaml",
            f"{self.kubify_dirs['API_SERVER_DIR']}/kube-scheduler.yaml",
            template_vars)


        for cur_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                self.config.get('controller', 'prefix'),
                self.get_node_domain(),
                cur_index)
            logging.info(f"creating control plane configs for {hostname}.")

            template_vars.update({
                'IP_ADDRESS': nodes[cur_index],
                'HOSTNAME': hostname})

            self.run_command(
                cmd=(f"mkdir -p {self.kubify_dirs['API_SERVER_DIR']}/{hostname}/"))

            self.write_template(
                f"{self.kubify_dirs['TEMPLATE_DIR']}/kube-apiserver.service",
                f"{self.kubify_dirs['API_SERVER_DIR']}/{hostname}/kube-apiserver.service",
                template_vars)


    @timeit
    def deploy_control_plane(self):
        """deploy kubernetes control plane configs/certs/binaries/services."""
        node_type = 'controller'
        nodes = self.config.get(node_type, 'ip_addresses').split(',')
        kube_bins = ['kube-apiserver', 'kube-controller-manager',
                     'kube-scheduler', 'kubectl']
        remote_user = self.config.get(node_type, 'remote_user')


        for node_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                self.config.get('controller', 'prefix'),
                self.get_node_domain(),
                node_index)

            logging.info(f"deploying kubernetes control plane on {hostname}")

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                f"sudo mkdir -p {self.kubify_dirs['INSTALL_DIR']}/bin/")

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                f"sudo mkdir -p {self.kubify_dirs['INSTALL_DIR']}/conf/")

            self.control_binaries(
                hostname,
                nodes[node_index],
                remote_user,
                'kube-controller-manager',
                'stop')

            self.control_binaries(
                hostname,
                nodes[node_index],
                remote_user,
                'kube-scheduler',
                'stop')

            self.control_binaries(
                hostname,
                nodes[node_index],
                remote_user,
                'kube-apiserver',
                'stop')

            for cur_file in kube_bins:
                self.deploy_file(
                    f"{self.kubify_dirs['BIN_DIR']}/{cur_file}",
                    remote_user,
                    nodes[node_index],
                    f"{self.kubify_dirs['INSTALL_DIR']}/bin/",
                    executable=True)

            self.deploy_file(
                (f"{self.kubify_dirs['ENCRYPTION_DIR']}/encryption-config.yaml "
                 f"{self.kubify_dirs['API_SERVER_DIR']}/kube-controller-manager.kubeconfig "
                 f"{self.kubify_dirs['API_SERVER_DIR']}/kube-scheduler.kubeconfig "
                 f"{self.kubify_dirs['API_SERVER_DIR']}/kube-scheduler.yaml"),
                remote_user,
                nodes[node_index],
                f"{self.kubify_dirs['INSTALL_DIR']}/conf/")

            self.deploy_file(
                (f"{self.kubify_dirs['API_SERVER_DIR']}/{hostname}/kube-apiserver.service "
                 f"{self.kubify_dirs['API_SERVER_DIR']}/kube-controller-manager.service "
                 f"{self.kubify_dirs['API_SERVER_DIR']}/kube-scheduler.service"),
                remote_user,
                nodes[node_index],
                '/etc/systemd/system/')

            self.deploy_file(
                (f"{self.kubify_dirs['API_SERVER_DIR']}/api-server.pem "
                 f"{self.kubify_dirs['API_SERVER_DIR']}/api-server-key.pem "
                 f"{self.kubify_dirs['CA_DIR']}/ca.pem "
                 f"{self.kubify_dirs['CA_DIR']}/ca-key.pem "
                 f"{self.kubify_dirs['API_SERVER_DIR']}/service-account.pem "
                 f"{self.kubify_dirs['API_SERVER_DIR']}/service-account-key.pem"),
                remote_user,
                nodes[node_index],
                f"{self.kubify_dirs['INSTALL_DIR']}/certs/")

            self.control_binaries(
                hostname,
                nodes[node_index],
                remote_user,
                'kube-controller-manager',
                'start')

            self.control_binaries(
                hostname,
                nodes[node_index],
                remote_user,
                'kube-apiserver',
                'start')

            self.control_binaries(
                hostname,
                nodes[node_index],
                remote_user,
                'kube-scheduler',
                'start')


    @timeit
    def create_ca_cert_private_key(self):
        """create ca cert and private key."""
        logging.info("beginning to create ca certificates")
        self.run_command(
            cmd=f"{self.kubify_dirs['BIN_DIR']}/cfssl gencert -initca {self.kubify_dirs['TEMPLATE_DIR']}/kubernetes-csr.json",
            output_file=f"{self.kubify_dirs['TMP_DIR']}/cfssl_initca.output")
        self.run_command(
            cmd=f"{self.kubify_dirs['BIN_DIR']}/cfssljson -bare -f {self.kubify_dirs['TMP_DIR']}/cfssl_initca.output {self.kubify_dirs['CA_DIR']}/ca")
        logging.info("finished creating ca certificates")


    @timeit
    def create_admin_client_cert(self):
        """create admin client certificate"""
        logging.info("beginning to create admin client certificates")
        self.run_command(
            cmd=(f"{self.kubify_dirs['BIN_DIR']}/cfssl gencert -ca={self.kubify_dirs['OUTPUT_DIR']}/ca/ca.pem "
                 f"-ca-key={self.kubify_dirs['OUTPUT_DIR']}/ca/ca-key.pem "
                 f"-config={self.kubify_dirs['TEMPLATE_DIR']}/ca-config.json "
                 f"-profile=kubernetes {self.kubify_dirs['TEMPLATE_DIR']}/admin-csr.json"),
            output_file=f"{self.kubify_dirs['TMP_DIR']}/cfssl_gencert_admin.output")

        self.run_command(
            cmd=(f"{self.kubify_dirs['BIN_DIR']}/cfssljson -bare -f {self.kubify_dirs['TMP_DIR']}/cfssl_gencert_admin.output "
                 f"{self.kubify_dirs['ADMIN_DIR']}/admin")
            )
        logging.info("finished creating admin client certificates")

    @timeit
    def create_kube_controller_manager_cert(self):
        """create controller manager certificate"""
        logging.info("beginning to create controller manager certificate")
        self.run_command(
            cmd=(f"{self.kubify_dirs['BIN_DIR']}/cfssl gencert -ca={self.kubify_dirs['OUTPUT_DIR']}/ca/ca.pem "
                 f"-ca-key={self.kubify_dirs['OUTPUT_DIR']}/ca/ca-key.pem "
                 f"-config={self.kubify_dirs['TEMPLATE_DIR']}/ca-config.json "
                 f"-profile=kubernetes {self.kubify_dirs['TEMPLATE_DIR']}/kube-controller-manager-csr.json"),
            output_file=f"{self.kubify_dirs['TMP_DIR']}/cfssl_gencert_kube_controller_manager.output")

        self.run_command(
            cmd=(f"{self.kubify_dirs['BIN_DIR']}/cfssljson -bare -f {self.kubify_dirs['TMP_DIR']}/cfssl_gencert_kube_controller_manager.output "
                 f"{self.kubify_dirs['API_SERVER_DIR']}/kube-controller-manager")
            )
        logging.info("finished creating controller manager certificate")

    @timeit
    def create_kube_service_account_certs(self):
        """create kube service account certificate"""
        logging.info("beginning to create service account certificate")
        self.run_command(
            cmd=(f"{self.kubify_dirs['BIN_DIR']}/cfssl gencert -ca={self.kubify_dirs['OUTPUT_DIR']}/ca/ca.pem "
                 f"-ca-key={self.kubify_dirs['OUTPUT_DIR']}/ca/ca-key.pem "
                 f"-config={self.kubify_dirs['TEMPLATE_DIR']}/ca-config.json "
                 f"-profile=kubernetes {self.kubify_dirs['TEMPLATE_DIR']}/kube-service-account-csr.json"),
            output_file=f"{self.kubify_dirs['TMP_DIR']}/cfssl_gencert_service_account.output")

        self.run_command(
            cmd=(f"{self.kubify_dirs['BIN_DIR']}/cfssljson -bare -f {self.kubify_dirs['TMP_DIR']}/cfssl_gencert_service_account.output "
                 f"{self.kubify_dirs['API_SERVER_DIR']}/service-account")
            )
        logging.info("finished creating controller manager certificate")

    @timeit
    def create_encryption_configs(self):
        """create kubernetes encryptionconfig file."""
        logging.info('beginning to create Kubernetes encryptionconfig file.')

        self.write_template(
            f"{self.kubify_dirs['TEMPLATE_DIR']}/encryption-config.yaml",
            f"{self.kubify_dirs['ENCRYPTION_DIR']}/encryption-config.yaml",
            {'key': self.config.get('general', 'encryption_key')}
        )

        logging.info('finished creating Kubernetes encryptionconfig file.')

    @timeit
    def deploy_encryption_configs(self):
        """deploy kubernetes encryptionconfig file."""
        node_type = 'controller'
        nodes = self.config.get(node_type, 'ip_addresses').split(',')
        remote_user = self.config.get(node_type, 'remote_user')
        prefix = self.config.get(node_type, 'prefix')

        logging.info('deploying encryptionconfig to controllers')
        for node_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(prefix,
                                                   self.get_node_domain(),
                                                   node_index)
            logging.debug(f'deploying encryptionconfig to {hostname}.')
            ec_file = f"{self.kubify_dirs['ENCRYPTION_DIR']}/encryption-config.yaml"

            self.deploy_file(
                f"{self.kubify_dirs['ENCRYPTION_DIR']}/encryption-config.yaml",
                remote_user,
                nodes[node_index],
                '/etc/ssl/certs/')

        logging.info('done deploying encryptionconfig to controllers')

    @timeit
    def create_etcd_certs(self, node_type):
        """create certificates for etcd peers."""
        for cur_index in range(0, self.get_node_count(node_type)):
            logging.info(f'creating etcd certs for node type {node_type}.')
            hostname = helpers.hostname_with_index(
                self.config.get(node_type, 'prefix'),
                self.get_node_domain(),
                cur_index)
            template_vars = {'HOSTNAME': hostname}

            self.write_template(
                f"{self.kubify_dirs['TEMPLATE_DIR']}/etcd-csr.json",
                f"{self.kubify_dirs['ETCD_DIR']}/{hostname}_etcd-csr.json",
                template_vars)

            logging.info(f'creating etcd certificate for host {hostname}.')
            self.run_command(
                cmd=(f"{self.kubify_dirs['BIN_DIR']}/cfssl gencert -ca={self.kubify_dirs['OUTPUT_DIR']}/ca/ca.pem "
                     f"-ca-key={self.kubify_dirs['OUTPUT_DIR']}/ca/ca-key.pem "
                     f"-config={self.kubify_dirs['TEMPLATE_DIR']}/ca-config.json "
                     "-profile=kubernetes "
                     f"-hostname={self.config.get(node_type, 'ip_addresses')},127.0.0.1 "
                     f"{self.kubify_dirs['ETCD_DIR']}/{hostname}_etcd-csr.json"),
                output_file=f"{self.kubify_dirs['ETCD_DIR']}/cfssl_gencert_etcd-{hostname}.output")

            self.run_command(
                cmd=(f"{self.kubify_dirs['BIN_DIR']}/cfssljson -bare "
                     f"-f {self.kubify_dirs['ETCD_DIR']}/cfssl_gencert_etcd-{hostname}.output "
                     f"-bare {self.kubify_dirs['ETCD_DIR']}/{hostname}-etcd"))


    @timeit
    def create_etcd_configs(self, node_type):
        nodes = self.config.get(node_type, 'ip_addresses').split(',')
        discovery_url = self.get_etcd_discovery_url(len(nodes))
        for cur_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                self.config.get(node_type, 'prefix'),
                self.get_node_domain(),
                cur_index)
            template_vars = {
                'HOSTNAME': hostname,
                'INSTALL_DIR': self.config.get('general', 'install_dir'),
                'CERTS_DIR': self.config.get('general', 'ssl_certs_dir'),
                'IP_ADDRESS': nodes[cur_index],
                'DISCOVERY_URL': discovery_url,
            }

            self.write_template(
                f"{self.kubify_dirs['TEMPLATE_DIR']}/etcd.service",
                f"{self.kubify_dirs['WORKER_DIR']}/{hostname}-etcd.service",
                template_vars)

    @timeit
    def create_kubelet_certs(self, node_type):
        """create certificates for kubernetes node kubelets."""
        for cur_index in range(0, self.get_node_count(node_type)):
            logging.info(f"creating kubelet-csr.json template for {node_type} node {cur_index}.")
            hostname = helpers.hostname_with_index(
                self.config.get(node_type, 'prefix'),
                self.get_node_domain(),
                cur_index)
            ip_address = self.get_node_ip_addresses(node_type).split(',')[cur_index]

            logging.debug(f'Hostname: {hostname}, IP Address: {ip_address}.')

            self.write_template(
                f"{self.kubify_dirs['TEMPLATE_DIR']}/kubelet-csr.json",
                f"{self.kubify_dirs['WORKER_DIR']}/{hostname}_kubelet-csr.json",
                {'HOSTNAME': hostname})

            logging.info(f'creating kubelet certificate for host {hostname}.')
            self.run_command(
                cmd=(f"{self.kubify_dirs['BIN_DIR']}/cfssl gencert -ca={self.kubify_dirs['OUTPUT_DIR']}/ca/ca.pem "
                     f"-ca-key={self.kubify_dirs['OUTPUT_DIR']}/ca/ca-key.pem "
                     f"-config={self.kubify_dirs['TEMPLATE_DIR']}/ca-config.json "
                     "-profile=kubernetes "
                     f"-hostname={hostname},{ip_address} "
                     f"{self.kubify_dirs['WORKER_DIR']}/{hostname}_kubelet-csr.json"),
                output_file=f"{self.kubify_dirs['WORKER_DIR']}/cfssl_gencert_kubelet-{hostname}.output")

            self.run_command(
                cmd=(f"{self.kubify_dirs['BIN_DIR']}/cfssljson -bare "
                     f"-f {self.kubify_dirs['WORKER_DIR']}/cfssl_gencert_kubelet-{hostname}.output "
                     f"-bare {self.kubify_dirs['WORKER_DIR']}/{hostname}-kubelet"))

    @timeit
    def create_kubelet_kubeconfigs(self, node_type):
        """create kubeconfigs for specified node_type ."""
        for cur_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                self.config.get(node_type, 'prefix'),
                self.get_node_domain(),
                cur_index)
            logging.info(f"creating kubelet kubeconfig for {hostname}.")
            self.run_command(
                f"{self.kubify_dirs['BIN_DIR']}/kubectl config set-cluster {self.config.get('general', 'cluster_name')} "
                f"--certificate-authority={self.kubify_dirs['CA_DIR']}/ca.pem "
                f"--embed-certs=true "
                f"--server=https://{self.config.get('general','api_server_ip_address')} "
                f"--kubeconfig={self.kubify_dirs['WORKER_DIR']}/{hostname}.kubeconfig")

            self.run_command(
                f"{self.kubify_dirs['BIN_DIR']}/kubectl config set-credentials "
                f"system:node:{hostname} "
                f"--client-certificate={self.kubify_dirs['WORKER_DIR']}/{hostname}-kubelet.pem "
                f"--client-key={self.kubify_dirs['WORKER_DIR']}/{hostname}-kubelet-key.pem "
                f"--embed-certs=true "
                f"--kubeconfig={self.kubify_dirs['WORKER_DIR']}/{hostname}.kubeconfig")

            self.run_command(
                f"{self.kubify_dirs['BIN_DIR']}/kubectl config set-context default "
                f"--cluster {self.config.get('general', 'cluster_name')} "
                f"--user=system:node:{hostname} "
                f"--kubeconfig={self.kubify_dirs['WORKER_DIR']}/{hostname}.kubeconfig")

            self.run_command(
                f"{self.kubify_dirs['BIN_DIR']}/kubectl config use-context default "
                f"--kubeconfig={self.kubify_dirs['WORKER_DIR']}/{hostname}.kubeconfig")

            logging.info(f"finished creating kubelet kubeconfig for {hostname}.")


    @timeit
    def create_kubeproxy_configs(self):
        """create kube-proxy kubeconfigs."""
        logging.info('creating kubeproxy kube, yaml, and service config.')

        self.run_command(
            f"{self.kubify_dirs['BIN_DIR']}/kubectl config set-cluster {self.config.get('general', 'cluster_name')} "
            f"--certificate-authority={self.kubify_dirs['CA_DIR']}/ca.pem "
            f"--embed-certs=true "
            f"--server=https://{self.config.get('general','api_server_ip_address')}:443 "
            f"--kubeconfig={self.kubify_dirs['PROXY_DIR']}/kube-proxy.kubeconfig")

        self.run_command(
            f"{self.kubify_dirs['BIN_DIR']}/kubectl config set-credentials system:kube-proxy "
            f"--client-certificate={self.kubify_dirs['PROXY_DIR']}/kube-proxy.pem "
            f"--client-key={self.kubify_dirs['PROXY_DIR']}/kube-proxy-key.pem "
            f"--embed-certs=true "
            f"--kubeconfig={self.kubify_dirs['PROXY_DIR']}/kube-proxy.kubeconfig")

        self.run_command(
            f"{self.kubify_dirs['BIN_DIR']}/kubectl config set-context default "
            f"--cluster={self.config.get('general', 'cluster_name')} "
            f'--user=system:kube-proxy '
            f"--kubeconfig={self.kubify_dirs['PROXY_DIR']}/kube-proxy.kubeconfig")

        self.run_command(
            f"{self.kubify_dirs['BIN_DIR']}/kubectl config use-context default "
            f"--kubeconfig={self.kubify_dirs['PROXY_DIR']}/kube-proxy.kubeconfig"
        )

        template_vars = {
            "INSTALL_DIR": self.config.get("general", "install_dir"),
            "CLUSTER_CIDR": self.config.get("general", "cluster_cidr")
        }

        self.write_template(
            f"{self.kubify_dirs['CHECKOUT_CONFIG_DIR']}/kube-proxy.yaml",
            f"{self.kubify_dirs['WORKER_DIR']}/kube-proxy.yaml",
            template_vars)

        self.write_template(
            f"{self.kubify_dirs['TEMPLATE_DIR']}/kube-proxy.service",
            f"{self.kubify_dirs['WORKER_DIR']}/kube-proxy.service",
            template_vars)

        logging.info('finished creating kubeproxy kube, yaml, and service config')

    @timeit
    def create_kubecontrollermanager_kubeconfig(self):
        """create kube-controller-manager kubeconfigs."""
        logging.info('creating kube-controller-manager kubeconfig.')
        self.run_command(
            f"{self.kubify_dirs['BIN_DIR']}/kubectl config set-cluster {self.config.get('general', 'cluster_name')} "
            f"--certificate-authority={self.kubify_dirs['CA_DIR']}/ca.pem "
            f'--embed-certs=true '
            f"--server=https://{self.config.get('general','api_server_ip_address')}:443 "
            f"--kubeconfig={self.kubify_dirs['API_SERVER_DIR']}/kube-controller-manager.kubeconfig")

        self.run_command(
            f"{self.kubify_dirs['BIN_DIR']}/kubectl config set-credentials system:kube-controller-manager "
            f"--client-certificate={self.kubify_dirs['API_SERVER_DIR']}/kube-controller-manager.pem "
            f"--client-key={self.kubify_dirs['API_SERVER_DIR']}/kube-controller-manager-key.pem "
            f"--embed-certs=true "
            f"--kubeconfig={self.kubify_dirs['API_SERVER_DIR']}/kube-controller-manager.kubeconfig")

        self.run_command(
            f"{self.kubify_dirs['BIN_DIR']}/kubectl config set-context default "
            f"--cluster={self.config.get('general', 'cluster_name')} "
            f"--user=system:kube-controller-manager "
            f"--kubeconfig={self.kubify_dirs['API_SERVER_DIR']}/kube-controller-manager.kubeconfig")

        self.run_command(
            f"{self.kubify_dirs['BIN_DIR']}/kubectl config use-context default "
            f"--kubeconfig={self.kubify_dirs['API_SERVER_DIR']}/kube-controller-manager.kubeconfig")

        logging.info('finished creating kube-controller-manager kubeconfig')


    @timeit
    def create_kubescheduler_kubeconfig(self):
        """create kube-scheduler kubeconfigs."""
        logging.info('creating kube-scheduler kubeconfig.')
        self.run_command(
            f"{self.kubify_dirs['BIN_DIR']}/kubectl config set-cluster {self.config.get('general', 'cluster_name')} "
            f"--certificate-authority={self.kubify_dirs['CA_DIR']}/ca.pem "
            f'--embed-certs=true '
            f"--server=https://{self.config.get('general','api_server_ip_address')} "
            f"--kubeconfig={self.kubify_dirs['API_SERVER_DIR']}/kube-scheduler.kubeconfig")

        self.run_command(
            f"{self.kubify_dirs['BIN_DIR']}/kubectl config set-credentials system:kube-scheduler "
            f"--client-certificate={self.kubify_dirs['API_SERVER_DIR']}/kube-scheduler.pem "
            f"--client-key={self.kubify_dirs['API_SERVER_DIR']}/kube-scheduler-key.pem "
            f"--embed-certs=true "
            f"--kubeconfig={self.kubify_dirs['API_SERVER_DIR']}/kube-scheduler.kubeconfig")

        self.run_command(
            f"{self.kubify_dirs['BIN_DIR']}/kubectl config set-context default "
            f"--cluster={self.config.get('general', 'cluster_name')} "
            f"--user=system:kube-scheduler "
            f"--kubeconfig={self.kubify_dirs['API_SERVER_DIR']}/kube-scheduler.kubeconfig")

        self.run_command(
            f"{self.kubify_dirs['BIN_DIR']}/kubectl config use-context default "
            f"--kubeconfig={self.kubify_dirs['API_SERVER_DIR']}/kube-scheduler.kubeconfig")

        logging.info('finished creating kube-scheduler kubeconfig')


    @timeit
    def create_kube_proxy_certs(self):
        """create kube-proxy certs"""
        logging.info("beginning to create kube-proxy certificates")
        self.run_command(
            cmd=(f"{self.kubify_dirs['BIN_DIR']}/cfssl gencert -ca={self.kubify_dirs['OUTPUT_DIR']}/ca/ca.pem "
                 f"-ca-key={self.kubify_dirs['OUTPUT_DIR']}/ca/ca-key.pem "
                 f"-config={self.kubify_dirs['TEMPLATE_DIR']}/ca-config.json "
                 f"-profile=kubernetes {self.kubify_dirs['TEMPLATE_DIR']}/kube-proxy-csr.json"),
            output_file=f"{self.kubify_dirs['TMP_DIR']}/cfssl_gencert_kube-proxy.output")

        self.run_command(
            cmd=(f"{self.kubify_dirs['BIN_DIR']}/cfssljson -bare -f {self.kubify_dirs['TMP_DIR']}/cfssl_gencert_kube-proxy.output "
                 f"{self.kubify_dirs['PROXY_DIR']}/kube-proxy")
            )
        logging.info("finished creating kube-proxy certificates")

    @timeit
    def create_kube_scheduler_certs(self):
        """create kube-scheduler certs"""
        logging.info("beginning to create kube-scheduler certificates")
        self.run_command(
            cmd=(f"{self.kubify_dirs['BIN_DIR']}/cfssl gencert -ca={self.kubify_dirs['OUTPUT_DIR']}/ca/ca.pem "
                 f"-ca-key={self.kubify_dirs['OUTPUT_DIR']}/ca/ca-key.pem "
                 f"-config={self.kubify_dirs['TEMPLATE_DIR']}/ca-config.json "
                 f"-profile=kubernetes {self.kubify_dirs['TEMPLATE_DIR']}/kube-scheduler-csr.json"),
            output_file=f"{self.kubify_dirs['TMP_DIR']}/cfssl_gencert_kube-scheduler.output")

        self.run_command(
            cmd=(f"{self.kubify_dirs['BIN_DIR']}/cfssljson "
                 f"-bare -f {self.kubify_dirs['TMP_DIR']}/cfssl_gencert_kube-scheduler.output "
                 f"{self.kubify_dirs['API_SERVER_DIR']}/kube-scheduler")
            )
        logging.info("finished creating kube-scheduler certificates")

    @timeit
    def create_api_server_cert(self):
        """create api-server cert."""
        logging.info("beginning to create api server certificates")
        controller_addresses = self.config.get('controller', 'ip_addresses')

        hostname_arg = (f"{controller_addresses},"
                        f"{helpers.get_ip_from_range(0, self.config.get('general', 'service_cidr'))},"
                        f"{self.config.get('general','api_server_ip_address')},"
                        "127.0.0.1,kubernetes.default")

        self.run_command(
            cmd=(f"{self.kubify_dirs['BIN_DIR']}/cfssl gencert -ca={self.kubify_dirs['OUTPUT_DIR']}/ca/ca.pem "
                 f"-ca-key={self.kubify_dirs['OUTPUT_DIR']}/ca/ca-key.pem "
                 f"-config={self.kubify_dirs['TEMPLATE_DIR']}/ca-config.json "
                 f"-hostname={hostname_arg} "
                 f"-profile=kubernetes "
                 f"{self.kubify_dirs['TEMPLATE_DIR']}/api-server-csr.json"),
            output_file=f"{self.kubify_dirs['TMP_DIR']}/cfssl_gencert_api_server.output")

        self.run_command(
            cmd=(f"{self.kubify_dirs['BIN_DIR']}/cfssljson -bare -f {self.kubify_dirs['TMP_DIR']}/cfssl_gencert_api_server.output "
                 f"{self.kubify_dirs['API_SERVER_DIR']}/api-server")
            )
        logging.info("finished creating api server certificates")

    @timeit
    def create_admin_kubeconfig(self):
        """create admin kubeconfig for remote access."""
        logging.info("creating admin kubeconfig for remote access.")

        self.run_command(
            (f"{self.kubify_dirs['BIN_DIR']}/kubectl config set-cluster {self.config.get('general', 'cluster_name')} "
             f"--certificate-authority={self.kubify_dirs['CA_DIR']}/ca.pem "
             f"--embed-certs=true "
             f"--server=https://{self.config.get('general','api_server_ip_address')} "
             f"--kubeconfig={self.kubify_dirs['ADMIN_DIR']}/admin.kubeconfig"))

        self.run_command(
            (f"{self.kubify_dirs['BIN_DIR']}/kubectl config set-credentials admin "
             f"--client-certificate={self.kubify_dirs['ADMIN_DIR']}/admin.pem "
             f"--client-key={self.kubify_dirs['ADMIN_DIR']}/admin-key.pem "
             f"--embed-certs=true "
             f"--kubeconfig={self.kubify_dirs['ADMIN_DIR']}/admin.kubeconfig"))

        self.run_command(
            (f"{self.kubify_dirs['BIN_DIR']}/kubectl config set-context {self.config.get('general', 'cluster_name')} "
             f"--cluster={self.config.get('general', 'cluster_name')} "
             f"--user=admin "
             f"--kubeconfig={self.kubify_dirs['ADMIN_DIR']}/admin.kubeconfig"))

        self.run_command(
            (f"{self.kubify_dirs['BIN_DIR']}/kubectl config use-context {self.config.get('general', 'cluster_name')} "
             f"--kubeconfig={self.kubify_dirs['ADMIN_DIR']}/admin.kubeconfig"))

        logging.info("done creating admin kubeconfig for remote access.")

    @timeit
    def create_cni_configs(self, node_type):
        """create CNI configs using run-time node->pod cidr data."""
        nodes = self.config.get(node_type, 'ip_addresses').split(',')
        remote_user = self.config.get(node_type, 'remote_user')
        prefix = self.config.get(node_type, 'prefix')
        template_vars = {}

        for node_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                prefix,
                self.get_node_domain(),
                node_index)

            logging.info(f"Writing CNI configs for node {hostname}")
            try:
                template_vars["POD_CIDR"]: self.node_pod_cidrs[hostname]
            except KeyError:
                logging.fatal("Unable to assign POD_CIDR for host {hostname}. "
                              "Current POD_CIDR dict: {self.node_pod_cidrs}")

            self.write_template(
                f"{self.kubify_dirs['TEMPLATE_DIR']}/cni/10-bridge.conf",
                f"{self.kubify_dirs['WORKER_DIR']}/{hostname}-10-bridge.conf",
                template_vars
            )
            logging.info(f"Done writing CNI configs for node {hostname}.")

    @timeit
    def deploy_cni_configs(self, node_type):
        """deploy cni configs."""
        nodes = self.config.get(node_type, 'ip_addresses').split(',')
        remote_user = self.config.get(node_type, 'remote_user')
        prefix = self.config.get(node_type, 'prefix')

        for node_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                prefix,
                self.get_node_domain(),
                node_index)
            logging.info(f"Deploying CNI configs to node {hostname}.")

            self.control_binaries(
                hostname,
                nodes[node_index],
                remote_user,
                'containerd',
                'stop')

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                'sudo mkdir -p /etc/cni/net.d')

            self.deploy_file(
                f"{self.kubify_dirs['WORKER_DIR']}/{hostname}-10-bridge.conf",
                remote_user,
                nodes[node_index],
                "/etc/cni/net.d/10-bridge.conf")

            self.deploy_file(
                f"{self.kubify_dirs['TEMPLATE_DIR']}/cni/99-loopback.conf",
                remote_user,
                nodes[node_index],
                "/etc/cni/net.d/")

            self.control_binaries(
                hostname,
                nodes[node_index],
                remote_user,
                'containerd',
                'start')

            logging.info(f"Finished deploying CNI configs to node {hostname}.")

    @timeit
    def deploy_etcd(self, node_type):
        """deploy etcd certs, configs and restart service."""
        nodes = self.config.get(node_type, 'ip_addresses').split(',')
        remote_user = self.config.get(node_type, 'remote_user')
        prefix = self.config.get(node_type, 'prefix')

        for node_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                prefix,
                self.get_node_domain(),
                node_index)

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                f"sudo mkdir -p {self.kubify_dirs['INSTALL_DIR']}/bin {self.kubify_dirs['INSTALL_DIR']}/certs")

            self.control_binaries(
                hostname,
                nodes[node_index],
                remote_user,
                'etcd',
                'stop')

            self.deploy_file(
                f"{self.kubify_dirs['WORKER_DIR']}/{hostname}-etcd.service",
                remote_user,
                nodes[node_index],
                '/etc/systemd/system/etcd.service')

            self.deploy_file(
                f"{self.kubify_dirs['CA_DIR']}/ca.pem",
                remote_user,
                nodes[node_index],
                f"{self.kubify_dirs['INSTALL_DIR']}/certs/")

            self.deploy_file(
                f"{self.kubify_dirs['ETCD_DIR']}/{hostname}-etcd.pem",
                remote_user,
                nodes[node_index],
                f"{self.kubify_dirs['INSTALL_DIR']}/certs/")

            self.deploy_file(
                f"{self.kubify_dirs['ETCD_DIR']}/{hostname}-etcd-key.pem",
                remote_user,
                nodes[node_index],
                f"{self.kubify_dirs['INSTALL_DIR']}/certs/")

            self.deploy_file(
                f"{self.kubify_dirs['BIN_DIR']}/etcd-v{self.config.get('general', 'etcd_version')}-linux-amd64/etcd",
                remote_user,
                nodes[node_index],
                f"{self.kubify_dirs['INSTALL_DIR']}/bin/etcd")

            self.deploy_file(
                f"{self.kubify_dirs['BIN_DIR']}/etcd-v{self.config.get('general', 'etcd_version')}-linux-amd64/etcdctl",
                remote_user,
                nodes[node_index],
                f"{self.kubify_dirs['INSTALL_DIR']}/bin/etcdctl")

            self.control_binaries(
                hostname,
                nodes[node_index],
                remote_user,
                'etcd',
                'daemon-reload')

            self.control_binaries(
                hostname,
                nodes[node_index],
                remote_user,
                'etcd',
                'enable')

            self.control_binaries(
                hostname,
                nodes[node_index],
                remote_user,
                'etcd',
                'start')

    @timeit
    def deploy_control_plane_rbac(self):
        """deploy control plane kubernetes rbac configs."""
        files = ['kube_apiserver_to_kubelet_clusterrole.yaml',
                 'kube_apiserver_to_kubelet_clusterrolebinding.yaml']

        logging.info('beginning to apply RBAC cluster role/binding yaml.')
        for cur_file in files:
            self.run_command(
                cmd=(f"{self.kubify_dirs['BIN_DIR']}/kubectl --kubeconfig={self.kubify_dirs['ADMIN_DIR']}/admin.kubeconfig "
                     f"apply -f {self.kubify_dirs['CHECKOUT_CONFIG_DIR']}/{cur_file}"))
        logging.info('finished applying RBAC cluster role/binding yaml.')

    @timeit
    def create_kubelet_configs(self, node_type):
        """create kubelet yaml and systemd configs for all nodes of node_type."""
        nodes = self.config.get(node_type, 'ip_addresses').split(',')
        remote_user = self.config.get(node_type, 'remote_user')
        prefix = self.config.get(node_type, 'prefix')

        for node_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                prefix,
                self.get_node_domain(),
                node_index)
            logging.info(f'creating kubelet config for {hostname}.')
            template_vars = {
                'HOSTNAME': hostname,
                'INSTALL_DIR': self.config.get('general', 'install_dir'),
                'CLUSTER_DNS': self.config.get('general', 'cluster_dns_ip_address')
            }
            self.write_template(
                f"{self.kubify_dirs['CHECKOUT_CONFIG_DIR']}/kubelet-config.yaml",
                f"{self.kubify_dirs['WORKER_DIR']}/{hostname}-kubelet-config.yaml",
                template_vars
            )

            self.write_template(
                f"{self.kubify_dirs['TEMPLATE_DIR']}/kubelet.service",
                f"{self.kubify_dirs['WORKER_DIR']}/{hostname}-kubelet.service",
                template_vars)

            logging.info(f'finished creating kubelet config for {hostname}.')

    @timeit
    def create_containerd_configs(self):
        """create containerd configs."""
        template_vars = {
            'INSTALL_DIR': self.config.get('general', 'install_dir')
        }
        logging.info('writing out containerd configs.')
        self.write_template(
            f"{self.kubify_dirs['CHECKOUT_CONFIG_DIR']}/containerd/containerd.service",
            f"{self.kubify_dirs['WORKER_DIR']}/containerd.service",
            template_vars)
        logging.info('finished writing out containerd configs.')


    @timeit
    def deploy_containerd(self, node_type):
        """deploy containerd to all nodes of node_type."""
        nodes = self.config.get(node_type, 'ip_addresses').split(',')
        remote_user = self.config.get(node_type, 'remote_user')
        prefix = self.config.get(node_type, 'prefix')

        for node_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                prefix,
                self.get_node_domain(),
                node_index)

            logging.info(f'deploying containerd to {hostname}.')

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                f"sudo mkdir -p {self.kubify_dirs['INSTALL_DIR']}/conf/")

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                'sudo mkdir -p /opt/cni/bin/')

            self.control_binaries(
                hostname,
                nodes[node_index],
                remote_user,
                'containerd',
                'stop')

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                'wget -O /tmp/containerd-1.2.0-rc.0.linux-amd64.tar.gz https://github.com/containerd/containerd/releases/download/v1.2.0-rc.0/containerd-1.2.0-rc.0.linux-amd64.tar.gz'
            )
            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                'sudo tar -xvzf /tmp/containerd-1.2.0-rc.0.linux-amd64.tar.gz -C /')

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                'wget -O /tmp/runc https://github.com/opencontainers/runc/releases/download/v1.0.0-rc5/runc.amd64'
            )
            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                'sudo mv /tmp/runc /usr/local/bin/')

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                'wget -O /tmp/runsc https://storage.googleapis.com/kubernetes-the-hard-way/runsc-50c283b9f56bb7200938d9e207355f05f79f0d17'
            )
            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                'sudo mv /tmp/runsc /usr/local/bin/')

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                'sudo chmod +x /usr/local/bin/runc')

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                'sudo chmod +x /usr/local/bin/runsc')

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                'wget -O /tmp/crictl-v1.12.0-linux-amd64.tar.gz https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.12.0/crictl-v1.12.0-linux-amd64.tar.gz'
            )
            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                'sudo tar -xvf /tmp/crictl-v1.12.0-linux-amd64.tar.gz -C /usr/local/bin/')

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                'wget -O /tmp/cni-plugins-amd64-v0.6.0.tgz https://github.com/containernetworking/plugins/releases/download/v0.6.0/cni-plugins-amd64-v0.6.0.tgz'
            )
            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                'sudo tar -xvf /tmp/cni-plugins-amd64-v0.6.0.tgz -C /opt/cni/bin/')

            self.deploy_file(
                f"{self.kubify_dirs['WORKER_DIR']}/containerd.service",
                remote_user,
                nodes[node_index],
                '/etc/systemd/system/containerd.service')

            self.deploy_file(
                f"{self.kubify_dirs['CHECKOUT_CONFIG_DIR']}/containerd/config.toml",
                remote_user,
                nodes[node_index],
                f"{self.kubify_dirs['INSTALL_DIR']}/conf/")

            self.control_binaries(
                hostname,
                nodes[node_index],
                remote_user,
                'containerd',
                'start')
            logging.info(f"finished deploying containerd to {hostname}.")


    @timeit
    def deploy_kubeproxy(self, node_type):
        """deploy kubeproxy to all nodes of node_type."""
        nodes = self.config.get(node_type, 'ip_addresses').split(',')
        remote_user = self.config.get(node_type, 'remote_user')
        prefix = self.config.get(node_type, 'prefix')

        for node_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                prefix,
                self.get_node_domain(),
                node_index)

            logging.info(f"beginning deploy of kubeproxy to {hostname}.")
            self.control_binaries(
                hostname,
                nodes[node_index],
                remote_user,
                'kube-proxy',
                'stop')

            self.deploy_file(
                f"{self.kubify_dirs['BIN_DIR']}/kube-proxy",
                remote_user,
                nodes[node_index],
                f"{self.kubify_dirs['INSTALL_DIR']}/bin/")

            self.deploy_file(
                f"{self.kubify_dirs['PROXY_DIR']}/kube-proxy.kubeconfig",
                remote_user,
                nodes[node_index],
                f"{self.kubify_dirs['INSTALL_DIR']}/conf/kube-proxy.kubeconfig")

            self.deploy_file(
                f"{self.kubify_dirs['WORKER_DIR']}/kube-proxy.service",
                remote_user,
                nodes[node_index],
                '/etc/systemd/system/kube-proxy.service')

            self.deploy_file(
                f"{self.kubify_dirs['WORKER_DIR']}/kube-proxy.yaml",
                remote_user,
                nodes[node_index],
                f"{self.kubify_dirs['INSTALL_DIR']}/conf/")

            self.control_binaries(
                hostname,
                nodes[node_index],
                remote_user,
                'kube-proxy',
                'start')

            logging.info(f"finishing deploy of kubeproxy to {hostname}.")

    @timeit
    def deploy_kubelet(self, node_type):
        """deploy kubelet to all nodes of node_type."""
        nodes = self.config.get(node_type, 'ip_addresses').split(',')
        remote_user = self.config.get(node_type, 'remote_user')
        prefix = self.config.get(node_type, 'prefix')

        for node_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                prefix,
                self.get_node_domain(),
                node_index)

            self.control_binaries(
                hostname,
                nodes[node_index],
                remote_user,
                'kubelet',
                'stop')

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                f"sudo mkdir -p {self.kubify_dirs['INSTALL_DIR']}/bin {self.kubify_dirs['INSTALL_DIR']}/conf")

            self.deploy_file(
                f"{self.kubify_dirs['BIN_DIR']}/kubelet",
                remote_user,
                nodes[node_index],
                f"{self.kubify_dirs['INSTALL_DIR']}/bin/")

            self.deploy_file(
                f"{self.kubify_dirs['WORKER_DIR']}/{hostname}.kubeconfig",
                remote_user,
                nodes[node_index],
                f"{self.kubify_dirs['INSTALL_DIR']}/conf/kubelet.kubeconfig")

            self.deploy_file(
                f"{self.kubify_dirs['WORKER_DIR']}/{hostname}-kubelet-config.yaml",
                remote_user,
                nodes[node_index],
                f"{self.kubify_dirs['INSTALL_DIR']}/conf/{hostname}-kubelet-config.yaml")

            self.deploy_file(
                f"{self.kubify_dirs['WORKER_DIR']}/{hostname}-kubelet.service",
                remote_user,
                nodes[node_index],
                '/etc/systemd/system/kubelet.service')

            self.deploy_file(
                f"{self.kubify_dirs['WORKER_DIR']}/{hostname}-kubelet.pem",
                remote_user,
                nodes[node_index],
                f"{self.kubify_dirs['INSTALL_DIR']}/certs/")

            self.deploy_file(
                f"{self.kubify_dirs['WORKER_DIR']}/{hostname}-kubelet-key.pem",
                remote_user,
                nodes[node_index],
                f"{self.kubify_dirs['INSTALL_DIR']}/certs/")

            self.control_binaries(
                hostname,
                nodes[node_index],
                remote_user,
                'kubelet',
                'start')

    @timeit
    def create_coredns_config(self):
        """create coredns yaml config."""

        logging.info('creating coredns service config')

        self.write_template(
            f"{self.kubify_dirs['TEMPLATE_DIR']}/core-dns.yaml",
            f"{self.kubify_dirs['ADDON_DIR']}/core-dns.yaml",
            {'CLUSTER_DNS_IP_ADDRESS': self.config.get(
                'general',
                'cluster_dns_ip_address')}
        )

        logging.info('finished creating coredns service config.')


    @timeit
    def deploy_coredns(self):
        """deploy coredns yaml config."""

        logging.info('deploying coredns')

        self.run_command(
            cmd=(f"{self.kubify_dirs['BIN_DIR']}/kubectl --kubeconfig {self.kubify_dirs['ADMIN_DIR']}/admin.kubeconfig "
                 f"apply -f {self.kubify_dirs['ADDON_DIR']}/core-dns.yaml"))

        logging.info('finished deploying coredns')


    @timeit
    def control_binaries(self, hostname, remote_ip, remote_user,
                         services, action=None):
        """control kubernetes binaries on a host."""

        if action == "stop":
            logging.info(f'stopping services {services} on {hostname}.')

            status_output = self.run_command_via_ssh(
                remote_user,
                remote_ip,
                f'sudo systemctl status {services}',
                ignore_errors=True,
                return_output=True)

            logging.debug(f"STATUS OUTPUT: {status_output}")
            if "could not be found" in status_output:
                logging.info(f"Service {services} could not be found. Skipping stop.")
            else:
                self.run_command_via_ssh(
                    remote_user,
                    remote_ip,
                    f'sudo systemctl stop {services}')

        if action == "start":
            logging.info(f'starting binaries on {hostname}.')

            self.run_command_via_ssh(
                remote_user,
                remote_ip,
                'sudo systemctl daemon-reload')

            self.run_command_via_ssh(
                remote_user,
                remote_ip,
                f'sudo systemctl enable {services}')

            self.run_command_via_ssh(
                remote_user,
                remote_ip,
                f"sudo systemctl start {services}")

    def apply_taints_and_labels(self, node_type):
        """apply various node taints and labels."""
        logging.info(f"applying node taints to {node_type} nodes.")

        for node_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                self.config.get(node_type, 'prefix'),
                self.get_node_domain(),
                node_index)

            logging.debug(f"applying node taint to {hostname}.")

            self.run_command(
                cmd=(f"{self.kubify_dirs['BIN_DIR']}/kubectl --kubeconfig={self.kubify_dirs['ADMIN_DIR']}/admin.kubeconfig "
                     f"taint nodes --overwrite {hostname} key=value:NoSchedule"))

            self.run_command(
                cmd=(f"{self.kubify_dirs['BIN_DIR']}/kubectl --kubeconfig={self.kubify_dirs['ADMIN_DIR']}/admin.kubeconfig "
                     f"label nodes --overwrite {hostname} role=controller"))

    @timeit
    def deploy_pod_security_policies(self):
        """deploy pod security policies and roles."""
        files = ['pod-security-policies.yaml',
                 'pod-security-policies-roles.yaml']

        for cur_file in files:
            logging.info(f'applying pod security policies: {cur_file}.')
            self.run_command(
                cmd=(f"{self.kubify_dirs['BIN_DIR']}/kubectl --kubeconfig={self.kubify_dirs['ADMIN_DIR']}/admin.kubeconfig "
                     f"apply -f {self.kubify_dirs['CHECKOUT_CONFIG_DIR']}/{cur_file}"))
        logging.info('finished applying pod security policies.')

    @timeit
    def deploy_kuberouter(self):
        """deploy kube-router."""
        self.run_command(
            cmd=(f"{self.kubify_dirs['BIN_DIR']}/kubectl "
                 f"--kubeconfig={self.kubify_dirs['ADMIN_DIR']}/admin.kubeconfig "
                 f"apply -f {self.kubify_dirs['CHECKOUT_CONFIG_DIR']}/kube-router.yaml"))

def main():
    """main for Kubify script."""
    parser = argparse.ArgumentParser(
        description='Install Kubernetes, the hard way.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--action",
                        choices=["create_certs", "create_configs", "deploy"],
                        action='append')
    parser.add_argument('--clear_output_dir',
                        dest='clear_output_dir',
                        action='store_true',
                        help=('delete the output directory before '
                              ' generating configs'))
    parser.add_argument('--config',
                        required=True,
                        help='kubify config file.')
    parser.add_argument('--dry_run',
                        action='store_true',
                        help='dont actually do anything.')
    parser.add_argument('--debug',
                        action='store_true',
                        help='enable debug-level logging.')
    parser.add_argument('--kube_ver',
                        dest='kube_ver',
                        help='kubernetes version',
                        default='1.14.0')
    parser.add_argument('--output_dir',
                        dest='output_dir',
                        required=True,
                        help=('base directory where generated configs '
                              'will be stored.'))
    parser.add_argument('--skip_tools_download',
                        action='store_true',
                        help=('Skip downloading the Kubernetes and cfssl binaries'))

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
