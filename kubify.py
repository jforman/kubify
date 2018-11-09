#!/usr/bin/env python

import argparse
import base64
import ConfigParser
import logging
import os
import shutil
import string
import subprocess
import sys
import time
import urllib

import helpers


class KubeBuild(object):
    """define, create, and deploy a kubernetes cluster methods."""

    def __init__(self, cli_args):
        self.args = cli_args
        self.checkout_path = os.path.dirname(os.path.realpath(sys.argv[0]))
        self.kube_release_dir = ('https://storage.googleapis.com/'
                                 'kubernetes-release/release/v%(ver)s'
                                 '/bin/linux/amd64' % {
                                     'ver': self.args.kube_ver,
                                 })

        self.config = ConfigParser.SafeConfigParser()
        self.config.read(self.args.config)
        self.node_pod_cidrs = {}

        logging.debug('Checkout Path: %s, Output Dir: %s',
                      self.checkout_path, self.args.output_dir)


    def timeit(method):
        def timed(*args, **kwargs):
            start_time = time.time()
            result = method(*args, **kwargs)
            end_time = time.time()

            logging.debug('execution info: method: %s, elapsed: %0.3fs.',
                          method.__name__, (end_time - start_time))
            return result
        return timed

    def get_node_domain(self):
        """return the node dns domain."""
        return self.config.get('general', 'domain_name')

    def get_etcd_discovery_url(self, cluster_size):
        """get the etcd discovery url for cluster size."""
        logging.info("Requesting new etcd discover URL. Cluster size: %s.",
            cluster_size)
        f = urllib.urlopen("https://discovery.etcd.io/new?size=%s" % cluster_size)
        disc_url = f.read()
        logging.info("Retrieved discovery URL: %s", disc_url)
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
            ("{BIN_DIR}/kubectl "
             "--kubeconfig {ADMIN_DIR}/admin.kubeconfig "
             "get nodes -o json"),
            return_output=True)
        node_json = json.loads(node_output)
        for item in node_json["items"]:
            node = item["metadata"]["name"]
            podcidr = item["spec"]["podCIDR"]
            self.node_pod_cidrs[node] = podcidr
            logging.info("Node %s has pod CIDR %s.", node, podcidr)

    @timeit
    def translate_path(self, path):
        """given string containing special macro, return command line with
        directories substituted in string."""

        path_dict = {
            '{CHECKOUT_DIR}': os.path.dirname(os.path.realpath(sys.argv[0])),
            '{OUTPUT_DIR}': self.args.output_dir,
        }

        # now we can update the dict path based upon the base ones above
        path_dict.update({
            '{ADDON_DIR}': os.path.join(path_dict['{OUTPUT_DIR}'], 'addon'),
            '{ADMIN_DIR}': os.path.join(path_dict['{OUTPUT_DIR}'], 'admin'),
            '{API_SERVER_DIR}': os.path.join(path_dict['{OUTPUT_DIR}'],
                                             'api_server'),
            '{BIN_DIR}': os.path.join(path_dict['{OUTPUT_DIR}'], 'bin'),
            '{CA_DIR}': os.path.join(path_dict['{OUTPUT_DIR}'], 'ca'),
            '{CONFIG_DIR}': os.path.join(path_dict['{CHECKOUT_DIR}'], 'configs'),
            '{ENCRYPTION_DIR}': os.path.join(path_dict['{OUTPUT_DIR}'],
                                             'encryption'),
            '{INSTALL_DIR}': self.config.get('general', 'install_dir'),
            '{ETCD_DIR}': os.path.join(path_dict['{OUTPUT_DIR}'], 'etcd'),
            '{PROXY_DIR}': os.path.join(path_dict['{OUTPUT_DIR}'], 'proxy'),
            '{SCRIPTS_DIR}': os.path.join(path_dict['{CHECKOUT_DIR}'],
                                          'scripts'),
            '{TEMPLATE_DIR}': os.path.join(path_dict['{CHECKOUT_DIR}'],
                                           'templates'),
            '{TMP_DIR}': os.path.join(path_dict['{OUTPUT_DIR}'], 'tmp'),
            '{WORKER_DIR}': os.path.join(path_dict['{OUTPUT_DIR}'], 'workers')

        })
        logging.debug('translating %s.', path)
        for key, value in path_dict.iteritems():
            path = string.replace(path, key, value)
        logging.debug('returning translated path %s.', path)
        return path

    @timeit
    def scp_file(self, local_path, remote_user, remote_host, remote_path,
                 ignore_errors=False):
        """copy the local file to the remote destination."""
        ssh_args = "-q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
        self.run_command(
            "scp %(ssh_args)s %(local_path)s "
            "%(remote_user)s@%(remote_host)s:%(remote_path)s" % {
                'ssh_args': ssh_args,
                'local_path': local_path,
                'remote_user': remote_user,
                'remote_host': remote_host,
                'remote_path': remote_path
            },
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
            "ssh %(ssh_args)s %(remote_user)s@%(remote_host)s "
            "%(command)s" % {
                'ssh_args': ssh_args,
                'remote_user': remote_user,
                'remote_host': remote_host,
                'command': command},
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
        local_path = self.translate_path(local_path)
        remote_path = self.translate_path(remote_path)
        self.scp_file(local_path, remote_user, remote_host, '~/')

        if executable:
            self.run_command_via_ssh(
                remote_user, remote_host,
                'chmod +x %(bare_filenames)s' % {'bare_filenames': bare_filenames_str})

        self.run_command_via_ssh(
            remote_user, remote_host,
            'sudo cp %(bare_filenames)s %(remote_path)s' % {
                'bare_filenames': bare_filenames_str,
                'remote_path': remote_path})


    @timeit
    def write_template(self, input_template, output_path, template_vars):
        """write a jinja2 template, with support for dry run and logging."""

        input_template_path = self.translate_path(input_template)
        rendered_output_path = self.translate_path(output_path)

        output = helpers.render_template(
            input_template_path,
            template_vars)

        if self.args.dry_run:
            logging.info('DRYRUN: would have written template '
                         '%s to %s.', input_template_path,
                         rendered_output_path)
        else:
            with open(rendered_output_path, 'w') as output_file:
                output_file.write(output)


    @timeit
    def build(self):
        """main build sequencer function."""
        self.create_output_dirs()
        self.download_tools()
        self.deploy_node_certs('controller')
        self.deploy_node_certs('worker')
        self.deploy_encryption_configs()

        self.bootstrap_control_plane_rbac()
        self.bootstrap_node('controller')
        self.bootstrap_node('worker')

        self.deploy_flannel()
        self.apply_taints_and_labels('controller')
        self.create_and_deploy_kube_dns()
        self.deploy_dashboard()
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

        if 'deploy' in self.args.action:
            self.deploy_etcd('controller')
            self.deploy_etcd('worker')
            self.deploy_control_plane()
            self.deploy_control_plane_rbac()
            self.deploy_containerd('controller')
            self.deploy_containerd('worker')
            self.deploy_kubelet('controller')
            self.deploy_kubelet('worker')

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



    @timeit
    def run_command(self, cmd, return_output=False,
                    cmd_stdin=None, write_output='', ignore_errors=False):
        """given a command, translate needed paths and run it."""
        command_list = self.translate_path(cmd).split()
        output = ""

        if self.args.dry_run:
            logging.info('DRYRUN: would have run %s.', " ".join(command_list))
        else:
            try:
                logging.debug('running %s', " ".join(command_list))
                output = subprocess.check_output(
                    command_list,
                    stdin=cmd_stdin,
                    )
                if output:
                    logging.debug("command output: %s", output)
            except subprocess.CalledProcessError as err:
                logging.fatal("Error in running %s. Output: %s",
                              command_list, err.output)
                if ignore_errors:
                    logging.info('ERROR IGNORED, continuing on.')
                else:
                    sys.exit(1)

        if write_output:
            out_file = self.translate_path(write_output)

            if self.args.dry_run:
                logging.debug('DRYRUN: writing output to %s.', out_file)
                return

            logging.debug("writing output to %s.", out_file)
            with open(out_file, 'w') as of:
                of.write(output)
            logging.debug("done writing output to %s.", out_file)

        if return_output:
            return output

    @timeit
    def create_output_dirs(self):
        """create the directory structure for storing create files."""
        subdirs = ['addon', 'addon/dashboard', 'admin', 'api_server', 'bin', 'ca', 'encryption',
                   'etcd', 'proxy', 'tmp', 'workers']

        if all([not self.args.clear_output_dir,
                os.path.exists(self.args.output_dir),
                not self.args.dry_run]):
            logging.fatal('output directory already exists, but you chose not '
                          'to clear it out first. are old configs still '
                          'present that you still want to save?')
            sys.exit(1)

        if os.path.exists(self.args.output_dir):
            if self.args.dry_run:
                logging.debug('DRYRUN: would have deleted %s.',
                              self.args.output_dir)
            else:
                shutil.rmtree(self.args.output_dir)

        if self.args.dry_run:
            logging.debug('DRYRUN: would have created %s.',
                          self.args.output_dir)
        else:
            os.makedirs(self.args.output_dir)

        for current_dir in subdirs:
            if self.args.dry_run:
                logging.debug('DRYRUN: create directory %s.',
                              os.path.join(self.args.output_dir,
                                           current_dir))
            else:
                os.makedirs(os.path.join(self.args.output_dir,
                                         current_dir))

    @timeit
    def download_tools(self):
        """download kubernetes cluster and cfssl cert creation binaries."""
        files_to_get = {
            'https://pkg.cfssl.org/R1.2/cfssl_linux-amd64':
            self.translate_path('{BIN_DIR}/cfssl'),
            'https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64':
            self.translate_path('{BIN_DIR}/cfssljson'),
            os.path.join(self.kube_release_dir, 'kubectl'):
            self.translate_path('{BIN_DIR}/kubectl'),
            os.path.join(self.kube_release_dir, 'kubelet'):
            self.translate_path('{BIN_DIR}/kubelet'),
            os.path.join(self.kube_release_dir, 'kube-apiserver'):
            self.translate_path('{BIN_DIR}/kube-apiserver'),
            os.path.join(self.kube_release_dir, 'kube-controller-manager'):
            self.translate_path('{BIN_DIR}/kube-controller-manager'),
            os.path.join(self.kube_release_dir, 'kube-proxy'):
            self.translate_path('{BIN_DIR}/kube-proxy'),
            os.path.join(self.kube_release_dir, 'kube-scheduler'):
            self.translate_path('{BIN_DIR}/kube-scheduler'),
            'https://github.com/etcd-io/etcd/releases/download/v%(ver)s/etcd-v%(ver)s-linux-amd64.tar.gz' % {
            'ver': self.config.get('general', 'etcd_version')}: self.translate_path('{BIN_DIR}/etcd-v%s.tar.gz' % self.config.get('general', 'etcd_version'))

        }

        logging.info("downloading new set of binary tools")
        for remotef, localf in files_to_get.iteritems():
            localf = self.translate_path(localf)
            if self.args.dry_run:
                logging.info("DRY RUN: would have downloaded %s to %s.",
                             remotef, localf)
                continue

            logging.debug('downloading %s to %s.', remotef, localf)
            urllib.urlretrieve(remotef, localf)
            os.chmod(localf, 0775)

        self.run_command(
            'tar -xvzf {BIN_DIR}/etcd-v%s.tar.gz -C {BIN_DIR}' % self.config.get('general', 'etcd_version'))

        logging.info("done downloading tools")

    @timeit
    def create_control_plane_configs(self):
        node_type = 'controller'
        nodes = self.config.get(node_type, 'ip_addresses').split(',')
        etcd_servers = ",".join(['https://%s:2379' % x for x in nodes])
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
            '{TEMPLATE_DIR}/kube-controller-manager.service',
            '{API_SERVER_DIR}/kube-controller-manager.service',
            template_vars)

        self.write_template(
            '{TEMPLATE_DIR}/kube-scheduler.service',
            '{API_SERVER_DIR}/kube-scheduler.service',
            template_vars)

        self.write_template(
            '{TEMPLATE_DIR}/kube-scheduler.yaml',
            '{API_SERVER_DIR}/kube-scheduler.yaml',
            template_vars)


        for cur_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                self.config.get('controller', 'prefix'),
                self.get_node_domain(),
                cur_index)
            logging.info('creating control plane configs for %s.',
                hostname)

            template_vars.update({
                'IP_ADDRESS': nodes[cur_index],
                'HOSTNAME': hostname})

            self.run_command(
                cmd=('mkdir -p {API_SERVER_DIR}/%s/' % hostname))

            self.write_template(
                '{TEMPLATE_DIR}/kube-apiserver.service',
                '{API_SERVER_DIR}/%s/kube-apiserver.service' % hostname,
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

            logging.info('deploying kubernetes control plane on %s.', hostname)

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                'sudo mkdir -p {INSTALL_DIR}/bin/')

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                'sudo mkdir -p {INSTALL_DIR}/conf/')

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
                    '{BIN_DIR}/%s' % cur_file,
                    remote_user,
                    nodes[node_index],
                    '{INSTALL_DIR}/bin/',
                    executable=True)

            self.deploy_file(
                ('{ENCRYPTION_DIR}/encryption-config.yaml '
                 '{API_SERVER_DIR}/kube-controller-manager.kubeconfig '
                 '{API_SERVER_DIR}/kube-scheduler.kubeconfig '
                 '{API_SERVER_DIR}/kube-scheduler.yaml'),
                remote_user,
                nodes[node_index],
                '{INSTALL_DIR}/conf/')

            self.deploy_file(
                ('{API_SERVER_DIR}/%s/kube-apiserver.service '
                 '{API_SERVER_DIR}/kube-controller-manager.service '
                 '{API_SERVER_DIR}/kube-scheduler.service ' % hostname),
                remote_user,
                nodes[node_index],
                '/etc/systemd/system/')

            self.deploy_file(
                ('{API_SERVER_DIR}/api-server.pem '
                 '{API_SERVER_DIR}/api-server-key.pem '
                 '{CA_DIR}/ca.pem '
                 '{CA_DIR}/ca-key.pem '
                 '{API_SERVER_DIR}/service-account.pem '
                 '{API_SERVER_DIR}/service-account-key.pem'),
                remote_user,
                nodes[node_index],
                '{INSTALL_DIR}/certs/')

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
            cmd="{BIN_DIR}/cfssl gencert -initca {TEMPLATE_DIR}/kubernetes-csr.json",
            write_output='{TMP_DIR}/cfssl_initca.output')
        self.run_command(
            cmd='{BIN_DIR}/cfssljson -bare -f {TMP_DIR}/cfssl_initca.output {CA_DIR}/ca')
        logging.info("finished creating ca certificates")


    @timeit
    def create_admin_client_cert(self):
        """create admin client certificate"""
        logging.info("beginning to create admin client certificates")
        self.run_command(
            cmd=("{BIN_DIR}/cfssl gencert -ca={OUTPUT_DIR}/ca/ca.pem "
                 "-ca-key={OUTPUT_DIR}/ca/ca-key.pem "
                 "-config={TEMPLATE_DIR}/ca-config.json "
                 "-profile=kubernetes {TEMPLATE_DIR}/admin-csr.json"),
            write_output='{TMP_DIR}/cfssl_gencert_admin.output')

        self.run_command(
            cmd=('{BIN_DIR}/cfssljson -bare -f {TMP_DIR}/cfssl_gencert_admin.output '
                 '{ADMIN_DIR}/admin')
            )
        logging.info("finished creating admin client certificates")

    @timeit
    def create_kube_controller_manager_cert(self):
        """create controller manager certificate"""
        logging.info("beginning to create controller manager certificate")
    def deploy_dashboard(self):
        """create dashboard certificate and deploy service/pods/etc."""
        logging.info("beginning to deploy dashboard")

        self.run_command(
            cmd=("{BIN_DIR}/cfssl gencert -ca={OUTPUT_DIR}/ca/ca.pem "
                 "-ca-key={OUTPUT_DIR}/ca/ca-key.pem "
                 "-config={TEMPLATE_DIR}/ca-config.json "
                 "-profile=kubernetes {TEMPLATE_DIR}/kube-controller-manager-csr.json"),
            write_output='{TMP_DIR}/cfssl_gencert_kube_controller_manager.output')

        self.run_command(
            cmd=('{BIN_DIR}/cfssljson -bare -f {TMP_DIR}/cfssl_gencert_kube_controller_manager.output '
                 '{API_SERVER_DIR}/kube-controller-manager')
            )
        logging.info("finished creating controller manager certificate")

    @timeit
    def create_kube_service_account_certs(self):
        """create kube service account certificate"""
        logging.info("beginning to create service account certificate")
        self.run_command(
            cmd=("{BIN_DIR}/cfssl gencert -ca={OUTPUT_DIR}/ca/ca.pem "
                 "-ca-key={OUTPUT_DIR}/ca/ca-key.pem "
                 "-config={TEMPLATE_DIR}/ca-config.json "
                 "-profile=kubernetes {TEMPLATE_DIR}/kube-service-account-csr.json"),
            write_output='{TMP_DIR}/cfssl_gencert_service_account.output')

        self.run_command(
            cmd=('{BIN_DIR}/cfssljson -bare -f {TMP_DIR}/cfssl_gencert_service_account.output '
                 '{API_SERVER_DIR}/service-account')
            )
        logging.info("finished creating controller manager certificate")


    @timeit
    def create_encryption_configs(self):
        """create kubernetes encryptionconfig file."""
        logging.info('beginning to create Kubernetes encryptionconfig file.')

        self.write_template(
            '{TEMPLATE_DIR}/encryption-config.yaml',
            '{ENCRYPTION_DIR}/encryption-config.yaml',
            {'key': base64.b64encode(os.urandom(32))}
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
            logging.debug('deploying encryptionconfig to %s.', hostname)
            ec_file = ("{ENCRYPTION_DIR}/encryption-config.yaml")

            self.deploy_file(
                '{ENCRYPTION_DIR}/encryption-config.yaml',
                remote_user,
                nodes[node_index],
                '/etc/ssl/certs/')

        logging.info('done deploying encryptionconfig to controllers')

    @timeit
    def create_etcd_certs(self, node_type):
        """create certificates for etcd peers."""
        for cur_index in range(0, self.get_node_count(node_type)):
            logging.info('creating etcd certs for node type %s.', node_type)
            hostname = helpers.hostname_with_index(
                self.config.get(node_type, 'prefix'),
                self.get_node_domain(),
                cur_index)
            template_vars = {'HOSTNAME': hostname}

            self.write_template(
                '{TEMPLATE_DIR}/etcd-csr.json',
                '{ETCD_DIR}/%s_etcd-csr.json' % hostname,
                template_vars)

            logging.info('creating etcd certificate for host %s', hostname)
            self.run_command(
                cmd=("{BIN_DIR}/cfssl gencert -ca={OUTPUT_DIR}/ca/ca.pem "
                     "-ca-key={OUTPUT_DIR}/ca/ca-key.pem "
                     "-config={TEMPLATE_DIR}/ca-config.json "
                     "-profile=kubernetes "
                     "-hostname=%(hostname_arg)s,127.0.0.1 "
                     "%(template_path)s" % {
                         'template_path': '{ETCD_DIR}/%s_etcd-csr.json' % hostname,
                         'hostname_arg': self.config.get(node_type, 'ip_addresses')}),
                write_output='{ETCD_DIR}/cfssl_gencert_etcd-%s.output' % hostname)

            self.run_command(
                cmd=("{BIN_DIR}/cfssljson -bare "
                     "-f {ETCD_DIR}/cfssl_gencert_etcd-%(hostname)s.output "
                     "-bare {ETCD_DIR}/%(hostname)s-etcd" % {
                         'hostname': hostname}))

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
                '{TEMPLATE_DIR}/etcd.service',
                '{WORKER_DIR}/%s-etcd.service' % hostname,
                template_vars)

    @timeit
    def create_kubelet_certs(self, node_type):
        """create certificates for kubernetes node kubelets."""
        for cur_index in range(0, self.get_node_count(node_type)):
            logging.info('creating kubelet-csr.json template for %s node %d.',
                         node_type, cur_index)
            hostname = helpers.hostname_with_index(
                self.config.get(node_type, 'prefix'),
                self.get_node_domain(),
                cur_index)
            ip_address = self.get_node_ip_addresses(node_type).split(',')[cur_index]

            logging.debug('Hostname: %s, IP Address: %s.',
                          hostname, ip_address)

            self.write_template(
                '{TEMPLATE_DIR}/kubelet-csr.json',
                '{WORKER_DIR}/%s_kubelet-csr.json' % hostname,
                {'HOSTNAME': hostname})

            logging.info('creating kubelet certificate for host %s', hostname)
            self.run_command(
                cmd=("{BIN_DIR}/cfssl gencert -ca={OUTPUT_DIR}/ca/ca.pem "
                     "-ca-key={OUTPUT_DIR}/ca/ca-key.pem "
                     "-config={TEMPLATE_DIR}/ca-config.json "
                     "-profile=kubernetes "
                     "-hostname=%(hostname)s,%(ip_address)s "
                     "%(template_path)s" % {
                         'hostname': hostname,
                         'ip_address': ip_address,
                         'template_path': '{WORKER_DIR}/%s_kubelet-csr.json' % hostname}),
                write_output='{WORKER_DIR}/cfssl_gencert_kubelet-%s.output' % hostname)

            self.run_command(
                cmd=("{BIN_DIR}/cfssljson -bare "
                     "-f {WORKER_DIR}/cfssl_gencert_kubelet-%(hostname)s.output "
                     "-bare {WORKER_DIR}/%(hostname)s-kubelet" % {'hostname': hostname}))

    @timeit
    def create_kubelet_kubeconfigs(self, node_type):
        """create kubeconfigs for specified node_type ."""
        for cur_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                self.config.get(node_type, 'prefix'),
                self.get_node_domain(),
                cur_index)
            logging.info('creating kubelet kubeconfig for %s.', hostname)
            self.run_command(
                '{BIN_DIR}/kubectl config set-cluster %(cluster_name)s '
                '--certificate-authority={CA_DIR}/ca.pem '
                '--embed-certs=true '
                '--server=https://%(api_server)s '
                '--kubeconfig={WORKER_DIR}/%(hostname)s.kubeconfig' % {
                    'cluster_name': self.config.get('general', 'cluster_name'),
                    'api_server': self.config.get(
                        'general',
                        'api_server_ip_address'),
                    'hostname': hostname})

            self.run_command(
                '{BIN_DIR}/kubectl config set-credentials '
                'system:node:%(hostname)s '
                '--client-certificate={WORKER_DIR}/%(hostname)s-kubelet.pem '
                '--client-key={WORKER_DIR}/%(hostname)s-kubelet-key.pem '
                '--embed-certs=true '
                '--kubeconfig={WORKER_DIR}/%(hostname)s.kubeconfig' % {
                    'hostname': hostname})

            self.run_command(
                '{BIN_DIR}/kubectl config set-context default '
                '--cluster %(cluster_name)s '
                '--user=system:node:%(hostname)s '
                '--kubeconfig={WORKER_DIR}/%(hostname)s.kubeconfig' % {
                    'cluster_name': self.config.get('general', 'cluster_name'),
                    'hostname': hostname})

            self.run_command(
                '{BIN_DIR}/kubectl config use-context default '
                '--kubeconfig={WORKER_DIR}/%(hostname)s.kubeconfig' % {
                    'hostname': hostname})
            logging.info('finished creating kubelet kubeconfig for %s.', hostname)


    @timeit
    def create_kubeproxy_configs(self):
        """create kube-proxy kubeconfigs."""
        logging.info('creating kubeproxy kube, yaml, and service config.')

        self.run_command(
            '{BIN_DIR}/kubectl config set-cluster %(cluster_name)s '
            '--certificate-authority={CA_DIR}/ca.pem '
            '--embed-certs=true '
            '--server=https://%(api_server)s:443 '
            '--kubeconfig={PROXY_DIR}/kube-proxy.kubeconfig' % {
                'api_server': self.config.get('general',
                                              'api_server_ip_address'),
                'cluster_name': self.config.get('general', 'cluster_name')})

        self.run_command(
            '{BIN_DIR}/kubectl config set-credentials system:kube-proxy '
            '--client-certificate={PROXY_DIR}/kube-proxy.pem '
            '--client-key={PROXY_DIR}/kube-proxy-key.pem '
            '--embed-certs=true '
            '--kubeconfig={PROXY_DIR}/kube-proxy.kubeconfig')

        self.run_command(
            '{BIN_DIR}/kubectl config set-context default '
            '--cluster=%(cluster_name)s '
            '--user=system:kube-proxy '
            '--kubeconfig={PROXY_DIR}/kube-proxy.kubeconfig' % {
                'cluster_name': self.config.get('general', 'cluster_name')
                })

        self.run_command(
            '{BIN_DIR}/kubectl config use-context default '
            '--kubeconfig={PROXY_DIR}/kube-proxy.kubeconfig'
        )

        template_vars = {
            "INSTALL_DIR": self.config.get("general", "install_dir"),
            "CLUSTER_CIDR": self.config.get("general", "cluster_cidr")
        }

        self.write_template(
            "{CONFIG_DIR}/kube-proxy.yaml",
            "{WORKER_DIR}/kube-proxy.yaml",
            template_vars)

        self.write_template(
            "{TEMPLATE_DIR}/kube-proxy.service",
            "{WORKER_DIR}/kube-proxy.service",
            template_vars)

        logging.info('finished creating kubeproxy kube, yaml, and service config')

    @timeit
    def create_kubecontrollermanager_kubeconfig(self):
        """create kube-controller-manager kubeconfigs."""
        logging.info('creating kube-controller-manager kubeconfig.')
        self.run_command(
            '{BIN_DIR}/kubectl config set-cluster %(cluster_name)s '
            '--certificate-authority={CA_DIR}/ca.pem '
            '--embed-certs=true '
            '--server=https://%(api_server)s:443 '
            '--kubeconfig={API_SERVER_DIR}/kube-controller-manager.kubeconfig' % {
                'api_server': self.config.get('general',
                                              'api_server_ip_address'),
                'cluster_name': self.config.get('general', 'cluster_name')})

        self.run_command(
            '{BIN_DIR}/kubectl config set-credentials system:kube-controller-manager '
            '--client-certificate={API_SERVER_DIR}/kube-controller-manager.pem '
            '--client-key={API_SERVER_DIR}/kube-controller-manager-key.pem '
            '--embed-certs=true '
            '--kubeconfig={API_SERVER_DIR}/kube-controller-manager.kubeconfig')

        self.run_command(
            '{BIN_DIR}/kubectl config set-context default '
            '--cluster=%(cluster_name)s '
            '--user=system:kube-controller-manager '
            '--kubeconfig={API_SERVER_DIR}/kube-controller-manager.kubeconfig' % {
                'cluster_name': self.config.get('general', 'cluster_name')
                })

        self.run_command(
            '{BIN_DIR}/kubectl config use-context default '
            '--kubeconfig={API_SERVER_DIR}/kube-controller-manager.kubeconfig'
        )
        logging.info('finished creating kube-controller-manager kubeconfig')


    @timeit
    def create_kubescheduler_kubeconfig(self):
        """create kube-scheduler kubeconfigs."""
        logging.info('creating kube-scheduler kubeconfig.')
        self.run_command(
            '{BIN_DIR}/kubectl config set-cluster %(cluster_name)s '
            '--certificate-authority={CA_DIR}/ca.pem '
            '--embed-certs=true '
            '--server=https://%(api_server)s:443 '
            '--kubeconfig={API_SERVER_DIR}/kube-scheduler.kubeconfig' % {
                'api_server': self.config.get('general',
                                              'api_server_ip_address'),
                'cluster_name': self.config.get('general', 'cluster_name')})

        self.run_command(
            '{BIN_DIR}/kubectl config set-credentials system:kube-scheduler '
            '--client-certificate={API_SERVER_DIR}/kube-scheduler.pem '
            '--client-key={API_SERVER_DIR}/kube-scheduler-key.pem '
            '--embed-certs=true '
            '--kubeconfig={API_SERVER_DIR}/kube-scheduler.kubeconfig')

        self.run_command(
            '{BIN_DIR}/kubectl config set-context default '
            '--cluster=%(cluster_name)s '
            '--user=system:kube-scheduler '
            '--kubeconfig={API_SERVER_DIR}/kube-scheduler.kubeconfig' % {
                'cluster_name': self.config.get('general', 'cluster_name')
                })

        self.run_command(
            '{BIN_DIR}/kubectl config use-context default '
            '--kubeconfig={API_SERVER_DIR}/kube-scheduler.kubeconfig'
        )
        logging.info('finished creating kube-scheduler kubeconfig')


    @timeit
    def create_kube_proxy_certs(self):
        """create kube-proxy certs"""
        logging.info("beginning to create kube-proxy certificates")
        self.run_command(
            cmd=("{BIN_DIR}/cfssl gencert -ca={OUTPUT_DIR}/ca/ca.pem "
                 "-ca-key={OUTPUT_DIR}/ca/ca-key.pem "
                 "-config={TEMPLATE_DIR}/ca-config.json "
                 "-profile=kubernetes {TEMPLATE_DIR}/kube-proxy-csr.json"),
            write_output='{TMP_DIR}/cfssl_gencert_kube-proxy.output')

        self.run_command(
            cmd=('{BIN_DIR}/cfssljson -bare -f {TMP_DIR}/cfssl_gencert_kube-proxy.output '
                 '{PROXY_DIR}/kube-proxy')
            )
        logging.info("finished creating kube-proxy certificates")

    @timeit
    def create_kube_scheduler_certs(self):
        """create kube-scheduler certs"""
        logging.info("beginning to create kube-scheduler certificates")
        self.run_command(
            cmd=("{BIN_DIR}/cfssl gencert -ca={OUTPUT_DIR}/ca/ca.pem "
                 "-ca-key={OUTPUT_DIR}/ca/ca-key.pem "
                 "-config={TEMPLATE_DIR}/ca-config.json "
                 "-profile=kubernetes {TEMPLATE_DIR}/kube-scheduler-csr.json"),
            write_output='{TMP_DIR}/cfssl_gencert_kube-scheduler.output')

        self.run_command(
            cmd=('{BIN_DIR}/cfssljson -bare -f {TMP_DIR}/cfssl_gencert_kube-scheduler.output '
                 '{API_SERVER_DIR}/kube-scheduler')
            )
        logging.info("finished creating kube-scheduler certificates")

    @timeit
    def create_api_server_cert(self):
        """create api-server cert."""
        logging.info("beginning to create api server certificates")
        controller_addresses = self.config.get('controller', 'ip_addresses')

        hostname_arg = ("%(controller_addresses)s,"
                        "%(kubernetes_service_ip_address)s,"
                        "%(api_server_ip_address)s,"
                        "127.0.0.1,kubernetes.default" % {
                            'controller_addresses': controller_addresses,
                            'kubernetes_service_ip_address': helpers.get_ip_from_range(
                                0, self.config.get('general', 'service_cidr')),
                            'api_server_ip_address': self.config.get(
                                'general',
                                'api_server_ip_address')
                            })

        self.run_command(
            cmd=("{BIN_DIR}/cfssl gencert -ca={OUTPUT_DIR}/ca/ca.pem "
                 "-ca-key={OUTPUT_DIR}/ca/ca-key.pem "
                 "-config={TEMPLATE_DIR}/ca-config.json "
                 "-hostname=%(hostname_arg)s "
                 "-profile=kubernetes "
                 "{TEMPLATE_DIR}/api-server-csr.json" % ({
                     'hostname_arg': hostname_arg,
                     })),
            write_output='{TMP_DIR}/cfssl_gencert_api_server.output')

        self.run_command(
            cmd=('{BIN_DIR}/cfssljson -bare -f {TMP_DIR}/cfssl_gencert_api_server.output '
                 '{API_SERVER_DIR}/api-server')
            )
        logging.info("finished creating api server certificates")

    @timeit
    def create_admin_kubeconfig(self):
        """create admin kubeconfig for remote access."""
        logging.info("creating admin kubeconfig for remote access.")

        self.run_command(
            ("{BIN_DIR}/kubectl config set-cluster %(cluster_name)s "
             "--certificate-authority={CA_DIR}/ca.pem "
             "--embed-certs=true "
             "--server=https://%(api_server_ip_address)s "
             "--kubeconfig={ADMIN_DIR}/kubeconfig " % {
                 'cluster_name': self.config.get('general', 'cluster_name'),
                 'api_server_ip_address': self.config.get('general',
                                                          'api_server_ip_address')
             }))

        self.run_command(
            ("{BIN_DIR}/kubectl config set-credentials admin "
             "--client-certificate={ADMIN_DIR}/admin.pem "
             "--client-key={ADMIN_DIR}/admin-key.pem "
             "--embed-certs=true "
             "--kubeconfig={ADMIN_DIR}/admin.kubeconfig"))

        self.run_command(
            ("{BIN_DIR}/kubectl config set-context %(cluster_name)s "
             "--cluster=%(cluster_name)s "
             "--user=admin "
             "--kubeconfig={ADMIN_DIR}/admin.kubeconfig" % {
                 'cluster_name': self.config.get('general', 'cluster_name')
             }
            ))

        self.run_command(
            ("{BIN_DIR}/kubectl config use-context %(cluster_name)s "
             "--kubeconfig={ADMIN_DIR}/admin.kubeconfig" % {
                 'cluster_name': self.config.get('general', 'cluster_name')
                 }))

        logging.info("done creating admin kubeconfig for remote access.")

    @timeit
    def create_cni_configs(self, node_type):
        """create CNI configs using run-time node->pod cidr data."""
        nodes = self.config.get(node_type, 'ip_addresses').split(',')
        remote_user = self.config.get(node_type, 'remote_user')
        prefix = self.config.get(node_type, 'prefix')

        for node_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                prefix,
                self.get_node_domain(),
                node_index)

            logging.info("Writing CNI configs for node %s.", hostname)
            template_vars = {
                "POD_CIDR": self.node_pod_cidrs[hostname]
            }

            self.write_template(
                "{TEMPLATE_DIR}/cni/10-bridge.conf",
                "{WORKER_DIR}/%s-10-bridge.conf" % hostname,
                template_vars
            )
            logging.info("Done writing CNI configs for node %s.", hostname)

    @timeit
    def deploy_cni_configs(self, node_type):
        """deploy cni configs."""
        nodes = self.config.get(node_type, 'ip_addresses').split(',')
        remote_user = self.config.get(node_type, 'remote_user')
        prefix = self.config.get(node_type, 'prefix')

        # TODO: do i need to restart anything? containerd?

        for node_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                prefix,
                self.get_node_domain(),
                node_index)
            logging.info("Deploying CNI configs to node %s.",  hostname)

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                'sudo mkdir -p /etc/cni/net.d')

            self.deploy_file(
                "{WORKER_DIR}/%s-10-bridge.conf" % hostname,
                remote_user,
                nodes[node_index],
                "/etc/cni/net.d/10-bridge.conf")

            self.deploy_file(
                "{TEMPLATE_DIR}/cni/99-loopback.conf",
                remote_user,
                nodes[node_index],
                "/etc/cni/net.d/")

            logging.info("Finished deploying CNI configs to node %s.",  hostname)

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
                'sudo mkdir -p {INSTALL_DIR}/bin {INSTALL_DIR}/certs')

            self.control_binaries(
                hostname,
                nodes[node_index],
                remote_user,
                'etcd',
                'stop')

            self.deploy_file(
                '{WORKER_DIR}/%s-etcd.service' % hostname,
                remote_user,
                nodes[node_index],
                '/etc/systemd/system/etcd.service')

            self.deploy_file(
                '{CA_DIR}/ca.pem',
                remote_user,
                nodes[node_index],
                '{INSTALL_DIR}/certs/')

            self.deploy_file(
                '{ETCD_DIR}/%s-etcd.pem' % hostname,
                remote_user,
                nodes[node_index],
                '{INSTALL_DIR}/certs/')

            self.deploy_file(
                '{ETCD_DIR}/%s-etcd-key.pem' % hostname,
                remote_user,
                nodes[node_index],
                '{INSTALL_DIR}/certs/')

            self.deploy_file(
                '{BIN_DIR}/etcd-v%s-linux-amd64/etcd' % self.config.get('general', 'etcd_version'),
                remote_user,
                nodes[node_index],
                '{INSTALL_DIR}/bin/etcd')

            self.deploy_file(
                '{BIN_DIR}/etcd-v%s-linux-amd64/etcdctl' % self.config.get('general', 'etcd_version'),
                remote_user,
                nodes[node_index],
                '{INSTALL_DIR}/bin/etcdctl')

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
    def bootstrap_control_plane_rbac(self):
        """bootstrap control plane kubernetes rbac configs."""
        files = ['kube_apiserver_to_kubelet_clusterrole.yaml',
                 'kube_apiserver_to_kubelet_clusterrolebinding.yaml']

        logging.info('beginning to apply RBAC cluster role/binding yaml.')
        for cur_file in files:
            self.run_command(
                cmd=('{BIN_DIR}/kubectl --kubeconfig={ADMIN_DIR}/admin.kubeconfig '
                     'apply -f {CONFIG_DIR}/%s' % cur_file))
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
            logging.info('creating kubelet config for %s.', hostname)
            template_vars = {
                'HOSTNAME': hostname,
                'INSTALL_DIR': self.config.get('general', 'install_dir')
            }
            self.write_template(
                '{CONFIG_DIR}/kubelet-config.yaml',
                '{WORKER_DIR}/%s-kubelet-config.yaml' % hostname,
                template_vars
            )

            self.write_template(
                '{TEMPLATE_DIR}/kubelet.service',
                '{WORKER_DIR}/%s-kubelet.service' % hostname,
                template_vars)

            logging.info('finished creating kubelet config for %s.', hostname)

    @timeit
    def create_containerd_configs(self):
        """create containerd configs."""
        template_vars = {
            'INSTALL_DIR': self.config.get('general', 'install_dir')
        }
        logging.info('writing out containerd configs.')
        self.write_template(
            '{CONFIG_DIR}/containerd/containerd.service',
            '{WORKER_DIR}/containerd.service',
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

            logging.info('deploying containerd to %s.', hostname)

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                'sudo mkdir -p {INSTALL_DIR}/conf/')

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
                'sudo chmod +x /usr/local/bin/runc /usr/local/bin/runsc')

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
                '{WORKER_DIR}/containerd.service',
                remote_user,
                nodes[node_index],
                '/etc/systemd/system/containerd.service')

            self.deploy_file(
                '{CONFIG_DIR}/containerd/config.toml',
                remote_user,
                nodes[node_index],
                '{INSTALL_DIR}/conf/')

            self.control_binaries(
                hostname,
                nodes[node_index],
                remote_user,
                'containerd',
                'start')
            logging.info('finished deploying containerd to %s.', hostname)


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

            logging.info("beginning deploy of kubeproxy to %s.", hostname)
            self.control_binaries(
                hostname,
                nodes[node_index],
                remote_user,
                'kube-proxy',
                'stop')

            self.deploy_file(
                '{BIN_DIR}/kube-proxy',
                remote_user,
                nodes[node_index],
                '{INSTALL_DIR}/bin/')

            self.deploy_file(
                '{PROXY_DIR}/kube-proxy.kubeconfig',
                remote_user,
                nodes[node_index],
                '{INSTALL_DIR}/conf/kube-proxy.kubeconfig')

            self.deploy_file(
                '{WORKER_DIR}/kube-proxy.service',
                remote_user,
                nodes[node_index],
                '/etc/systemd/system/kube-proxy.service')

            self.deploy_file(
                '{WORKER_DIR}/kube-proxy.yaml',
                remote_user,
                nodes[node_index],
                '{INSTALL_DIR}/conf/')

            self.control_binaries(
                hostname,
                nodes[node_index],
                remote_user,
                'kube-proxy',
                'start')

            logging.info("finishing deploy of kubeproxy to %s.", hostname)

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
                'sudo mkdir -p {INSTALL_DIR}/bin {INSTALL_DIR}/conf')

            self.deploy_file(
                '{BIN_DIR}/kubelet',
                remote_user,
                nodes[node_index],
                '{INSTALL_DIR}/bin/')

            self.deploy_file(
                '{WORKER_DIR}/%s.kubeconfig' % hostname,
                remote_user,
                nodes[node_index],
                '{INSTALL_DIR}/conf/kubelet.kubeconfig')

            self.deploy_file(
                '{WORKER_DIR}/%s-kubelet-config.yaml' % hostname,
                remote_user,
                nodes[node_index],
                '{INSTALL_DIR}/conf/%s-kubelet-config.yaml' % hostname)

            self.deploy_file(
                '{WORKER_DIR}/%s-kubelet.service' % hostname,
                remote_user,
                nodes[node_index],
                '/etc/systemd/system/kubelet.service')

            self.deploy_file(
                '{WORKER_DIR}/%s-kubelet.pem' % hostname,
                remote_user,
                nodes[node_index],
                '{INSTALL_DIR}/certs/')

            self.deploy_file(
                '{WORKER_DIR}/%s-kubelet-key.pem' % hostname,
                remote_user,
                nodes[node_index],
                '{INSTALL_DIR}/certs/')

            self.control_binaries(
                hostname,
                nodes[node_index],
                remote_user,
                'kubelet',
                'start')

    @timeit
    def create_and_deploy_kube_dns(self):
        """create kube-dns add-on yaml and deploy it to cluster."""

        logging.info('generating and applying kube-dns service template')

        self.write_template(
            '{TEMPLATE_DIR}/kube-dns.yaml',
            '{ADDON_DIR}/kube-dns.yaml',
            {'CLUSTER_DNS_IP_ADDRESS': self.config.get(
                'general',
                'cluster_dns_ip_address')}
        )

        self.run_command(
            ('{BIN_DIR}/kubectl apply -f {ADDON_DIR}/kube-dns.yaml '
             '--kubeconfig={ADMIN_DIR}/kubeconfig '))

        logging.info('finished applying kube-dns service template.')

    @timeit
    def control_binaries(self, hostname, remote_ip, remote_user,
                         services, action=None):
        """control kubernetes binaries on a host."""

        if action == "stop":
            logging.info('stopping services %s on %s.', services, hostname)
            stop_output = self.run_command_via_ssh(
                remote_user,
                remote_ip,
                'sudo systemctl stop %s' % services,
                ignore_errors=True,
                return_output=True)

            if 'not loaded.' in stop_output:
                logging.info("Service %s not found. Service does not exist yet "
                             "so not an error.", services)
            else:
                logging.fatal("Unable to stop service %s.", services)

        if action == "start":
            logging.info('starting binaries on %s.', hostname)

            self.run_command_via_ssh(
                remote_user,
                remote_ip,
                'sudo systemctl daemon-reload')

            self.run_command_via_ssh(
                remote_user,
                remote_ip,
                'sudo systemctl enable %s'% services)

            self.run_command_via_ssh(
                remote_user,
                remote_ip,
                'sudo systemctl start %s' % services)

    def apply_taints_and_labels(self, node_type):
        """apply various node taints and labels."""
        logging.info('applying node taints to %s nodes.', node_type)

        for node_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                self.config.get(node_type, 'prefix'),
                self.get_node_domain(),
                node_index)

            logging.debug('applying node taint to %s.', hostname)

            self.run_command(
                cmd=('{BIN_DIR}/kubectl --kubeconfig={ADMIN_DIR}/kubeconfig '
                     'taint nodes --overwrite %(hostname)s '
                     'node-role.kubernetes.io/master='':NoSchedule' % {
                         'hostname': hostname}))
            self.run_command(
                cmd=('{BIN_DIR}/kubectl --kubeconfig={ADMIN_DIR}/kubeconfig '
                     'label nodes --overwrite %(hostname)s '
                     'role=controller' % { 'hostname': hostname}))

    @timeit
    def deploy_flannel(self):
        """deploy flannel overlay network."""
        self.run_command(
            cmd=('{BIN_DIR}/kubectl --kubeconfig={ADMIN_DIR}/kubeconfig '
                 'apply -f https://raw.githubusercontent.com/coreos/flannel/'
                 'master/Documentation/kube-flannel.yml'))


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
                        default='1.9.0')
    parser.add_argument('--output_dir',
                        dest='output_dir',
                        required=True,
                        help=('base directory where generated configs '
                              'will be stored.'))

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
    k8s = KubeBuild(args)
    k8s.build()
    end_time = time.time()
    elapsed_time = end_time - start_time
    logging.info('completed running kubernetes build. Elapsed Time %s.',
                 time.strftime("%Hh:%Mm:%Ss", time.gmtime(elapsed_time)))


if __name__ == '__main__':
    main()
