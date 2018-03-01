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

        logging.debug('Checkout Path: %s, Output Dir: %s',
                      self.checkout_path, self.args.output_dir)

    def get_node_domain(self):
        """return the node dns domain."""
        return self.config.get('general', 'domain_name')

    def get_ssl_certificate_fields(self):
        """return the ssl field names as a dict."""
        return dict(self.config.items('certificate'))

    def get_node_ip_addresses(self, node_type):
        """get list of node IPs."""
        return self.config.get(node_type, 'ip_addresses')

    def get_node_count(self, node_type):
        """get number of nodes of a particular type."""
        return len(self.get_node_ip_addresses(node_type).split(','))

    def translate_path(self, path):
        """given string containing special macro, return command line with
        directories substituted in string."""

        # first define the base directories
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


    def write_template(self, input_template, output_path, template_vars):
        """write a jinja2 template, with support for dry run and logging."""

        input_template_path = self.translate_path(input_template)
        rendered_output_path = self.translate_path(output_path)

        output = helpers.render_template(
            input_template_path,
            template_vars)

        if self.args.dry_run:
            logging.info('DRYRUN: would have written template '
                         '%(input_template)s to %(output_path)s.' % {
                             'input_template': input_template_path,
                             'output_path': rendered_output_path})
        else:
            with open(rendered_output_path, 'w') as output_file:
                output_file.write(output)


    def build(self):
        """main build sequencer function."""
        self.create_output_dirs()
        self.download_tools()
        self.create_ca_cert_private_key()
        self.create_admin_client_cert()
        self.create_node_certs('worker')
        self.create_node_certs('controller')
        self.create_proxy_certs()
        self.create_api_server_cert()
        self.create_etcd_certs('controller')
        self.create_etcd_certs('worker')
        self.create_kubelet_kubeconfigs('controller')
        self.create_kubelet_kubeconfigs('worker')
        self.create_kubeproxy_kubeconfigs()
        self.create_encryption_configs()

        self.deploy_etcd_certs('controller')
        self.deploy_etcd_certs('worker')
        self.deploy_node_certs('controller')
        self.deploy_node_certs('worker')
        self.deploy_worker_kubeproxy_kubeconfigs()
        self.deploy_encryption_configs()

        self.bootstrap_control_plane()
        self.bootstrap_control_plane_rbac()
        self.bootstrap_node('controller')
        self.bootstrap_node('worker')

        self.create_admin_kubeconfig()
        self.apply_taints('controller')
        self.deploy_flannel()
        self.create_and_deploy_kube_dns()
        self.deploy_dashboard()

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


    def deploy_node_certs(self, node_type):
        """copy the certificates to kubernetes nodes of node_type."""
        nodes = self.config.get(node_type, 'ip_addresses').split(',')
        remote_user = self.config.get(node_type, 'remote_user')
        prefix = self.config.get(node_type, 'prefix')

        logging.debug('deploying %s certificates.', node_type)
        for node_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(prefix,
                                                   self.get_node_domain(),
                                                   node_index)
            logging.debug('deploying %s certificates to %s.', node_type,
                          hostname)

            if node_type == 'controller':
                pem_files = ("{CA_DIR}/ca.pem "
                             "{CA_DIR}/ca-key.pem "
                             "{API_SERVER_DIR}/kubernetes-key.pem "
                             "{API_SERVER_DIR}/kubernetes.pem "
                             "{WORKER_DIR}/%(hostname)s.pem "
                             "{WORKER_DIR}/%(hostname)s-key.pem " % {
                                 'hostname': hostname})
            else:
                pem_files = ("{CA_DIR}/ca.pem "
                             "{WORKER_DIR}/%(hostname)s.pem "
                             "{WORKER_DIR}/%(hostname)s-key.pem " % {
                                 'hostname': hostname})


            self.scp_file(
                pem_files,
                remote_user,
                nodes[node_index],
                '~/')

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                'sudo mkdir -p /var/lib/kubernetes/ /var/lib/kubelet/')

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                'sudo cp ca.pem /var/lib/kubernetes/')


            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                'sudo cp %(hostname)s-key.pem %(hostname)s.pem /var/lib/kubelet/' % {
                    'hostname': hostname
                    }
                )

            if node_type == 'controller':
                self.run_command_via_ssh(
                    remote_user,
                    nodes[node_index],
                    'sudo cp ca-key.pem /var/lib/kubernetes/')

        logging.debug('finished deploying %s certificates.', node_type)


    def deploy_worker_kubeproxy_kubeconfigs(self):
        """copy the certificates to kubernetes worker nodes."""
        node_type = 'worker'
        nodes = self.config.get(node_type, 'ip_addresses').split(',')
        remote_user = self.config.get(node_type, 'remote_user')
        prefix = self.config.get(node_type, 'prefix')

        logging.debug('deploying kubeconfigs to workers')
        for node_index in range(0, self.get_node_count('worker')):
            hostname = helpers.hostname_with_index(prefix,
                                                   self.get_node_domain(),
                                                   node_index)
            logging.debug('deploying kubeconfig to %s.', hostname)
            kubeconfig_files = (
                "{WORKER_DIR}/%(hostname)s.kubeconfig "
                "{PROXY_DIR}/kube-proxy.kubeconfig" % {
                    'hostname': hostname})

            self.scp_file(
                kubeconfig_files,
                remote_user,
                nodes[node_index],
                '~/')

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

        logging.info("done downloading tools")

    def bootstrap_control_plane(self):
        """bootstrap kubernetes components on the controller hosts."""
        node_type = 'controller'
        nodes = self.config.get(node_type, 'ip_addresses').split(',')
        etcd_servers = ",".join(['https://%s:2379' % x for x in nodes])
        install_dir = self.config.get('general', 'install_dir')
        kube_bins = ['kube-apiserver', 'kube-controller-manager',
                     'kube-scheduler', 'kubectl']
        remote_user = self.config.get(node_type, 'remote_user')

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

        # write kube-scheduler
        self.write_template(
            '{TEMPLATE_DIR}/kube-scheduler.service',
            '{API_SERVER_DIR}/kube-scheduler.service',
            template_vars)

        logging.info('bootstraping kubernetes on %s nodes.', node_type)

        for cur_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                self.config.get('controller', 'prefix'),
                self.get_node_domain(),
                cur_index)
            logging.info('bootstrapping %s for kubernetes.', hostname)
            self.run_command_via_ssh(
                remote_user,
                nodes[cur_index],
                'sudo mkdir -p %(install_dir)s/bin/' % {
                    'install_dir': install_dir}
            )

            self.run_command_via_ssh(
                remote_user,
                nodes[cur_index],
                'sudo systemctl stop kube-scheduler.service',
                ignore_errors=True)

            self.run_command_via_ssh(
                remote_user,
                nodes[cur_index],
                'sudo systemctl stop kube-controller-manager.service',
                ignore_errors=True)

            self.run_command_via_ssh(
                remote_user,
                nodes[cur_index],
                'sudo systemctl stop kube-apiserver.service',
                ignore_errors=True)

            for cur_file in kube_bins:
                self.scp_file(
                    '{BIN_DIR}/%s' % cur_file,
                    remote_user,
                    nodes[cur_index],
                    '~')
                self.run_command_via_ssh(
                    remote_user,
                    nodes[cur_index],
                    'sudo cp %(cur_file)s %(install_dir)s/bin/' % {
                        'cur_file': cur_file,
                        'install_dir': install_dir
                    }
                )
                self.run_command_via_ssh(
                    remote_user,
                    nodes[cur_index],
                    'sudo chmod +x %(install_dir)s/bin/%(cur_file)s' % {
                        'cur_file': cur_file,
                        'install_dir': install_dir,
                    }
                )

            template_vars.update({'IP_ADDRESS': nodes[cur_index]})

            self.write_template(
                '{TEMPLATE_DIR}/kube-apiserver.service',
                '{API_SERVER_DIR}/%s-kube-apiserver.service' % hostname,
                template_vars)

            self.scp_file(
                '{API_SERVER_DIR}/%s-kube-apiserver.service' % hostname,
                remote_user,
                nodes[cur_index],
                '~/kube-apiserver.service'
                )

            self.scp_file(
                '{API_SERVER_DIR}/kube-controller-manager.service',
                remote_user,
                nodes[cur_index],
                '~/',
                )

            self.scp_file(
                '{API_SERVER_DIR}/kube-scheduler.service',
                remote_user,
                nodes[cur_index],
                '~/',
                )

            self.run_command_via_ssh(
                remote_user,
                nodes[cur_index],
                ('sudo cp kube-apiserver.service kube-scheduler.service '
                 'kube-controller-manager.service /etc/systemd/system/'))

            self.run_command_via_ssh(
                remote_user,
                nodes[cur_index],
                ('sudo cp kubernetes.pem kubernetes-key.pem ca.pem ca-key.pem '
                 '/etc/ssl/certs/')
            )

            self.run_command_via_ssh(
                remote_user,
                nodes[cur_index],
                'sudo systemctl daemon-reload')

            self.run_command_via_ssh(
                remote_user,
                nodes[cur_index],
                ('sudo systemctl enable kube-apiserver kube-controller-manager '
                 'kube-scheduler'))

            self.run_command_via_ssh(
                remote_user,
                nodes[cur_index],
                ('sudo systemctl start kube-apiserver kube-controller-manager '
                 'kube-scheduler'))


    def create_ca_cert_private_key(self):
        """create ca cert and private key."""
        logging.info("beginning to create ca certificates")
        self.run_command(
            cmd="{BIN_DIR}/cfssl gencert -initca {TEMPLATE_DIR}/ca-csr.json",
            write_output='{TMP_DIR}/cfssl_initca.output')
        self.run_command(
            cmd='{BIN_DIR}/cfssljson -bare -f {TMP_DIR}/cfssl_initca.output {CA_DIR}/ca')
        logging.info("finished creating ca certificates")


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


    def deploy_dashboard(self):
        """create dashboard certificate and deploy service/pods/etc."""
        logging.info("beginning to deploy dashboard")

        self.run_command(
            cmd=("{BIN_DIR}/cfssl gencert -ca={OUTPUT_DIR}/ca/ca.pem "
                 "-ca-key={OUTPUT_DIR}/ca/ca-key.pem "
                 "-config={TEMPLATE_DIR}/ca-config.json "
                 "-hostname=%(hostname)s "
                 "-profile=kubernetes {TEMPLATE_DIR}/kubernetes-csr.json" % {
                     'hostname': self.config.get('general', 'dashboard_fqdn')}),
            write_output='{TMP_DIR}/cfssl_gencert_dashboard.output')

        self.run_command(
            cmd=('{BIN_DIR}/cfssljson -bare -f {TMP_DIR}/cfssl_gencert_dashboard.output '
                 '{ADDON_DIR}/dashboard/dashboard')
            )

        self.run_command(
            cmd='mv {ADDON_DIR}/dashboard/dashboard-key.pem {ADDON_DIR}/dashboard/dashboard.key')

        self.run_command(
            cmd='mv {ADDON_DIR}/dashboard/dashboard.pem {ADDON_DIR}/dashboard/dashboard.crt')

        # There is no 'apply' for a secret, so when creating a secret,
        # if it already exists, you error out. I'm not a fan, but for now
        # this works.
        self.run_command(
            cmd=('{BIN_DIR}/kubectl --kubeconfig={ADMIN_DIR}/kubeconfig '
                 'create secret generic kubernetes-dashboard-certs '
                 '--from-file={ADDON_DIR}/dashboard/ -n kube-system'),
            ignore_errors=True)

        self.run_command(
            cmd=('{BIN_DIR}/kubectl --kubeconfig={ADMIN_DIR}/kubeconfig apply '
                 '-f https://raw.githubusercontent.com/kubernetes/dashboard/'
                 'master/src/deploy/recommended/kubernetes-dashboard.yaml'))

        logging.info("finished deploying dashboard")

    def create_encryption_configs(self):
        """create kubernetes encryptionconfig file."""
        logging.info('beginning to create Kubernetes encryptionconfig file.')

        self.write_template(
            '{TEMPLATE_DIR}/encryption-config.yaml',
            '{ENCRYPTION_DIR}/encryption-config.yaml',
            {'key': base64.b64encode(os.urandom(32))}
        )

        logging.info('finished creating Kubernetes encryptionconfig file.')

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

            self.scp_file(
                ec_file,
                remote_user,
                nodes[node_index],
                '~/')

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                'sudo cp encryption-config.yaml /etc/ssl/certs/'
            )

        logging.info('done deploying encryptionconfig to controllers')

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

    def create_node_certs(self, node_type):
        """create certificates for kubernetes nodes."""
        for cur_index in range(0, self.get_node_count(node_type)):
            logging.info('creating node-csr.json template for %s node %d.',
                         node_type, cur_index)
            hostname = helpers.hostname_with_index(
                self.config.get(node_type, 'prefix'),
                self.get_node_domain(),
                cur_index)
            ip_address = self.get_node_ip_addresses(node_type).split(',')[cur_index]

            logging.debug('Hostname: %s, IP Address: %s.',
                          hostname, ip_address)

            self.write_template(
                '{TEMPLATE_DIR}/node-csr.json',
                '{WORKER_DIR}/%s_node-csr.json' % hostname,
                {'HOSTNAME': hostname})

            logging.info('creating node certificate for host %s', hostname)
            self.run_command(
                cmd=("{BIN_DIR}/cfssl gencert -ca={OUTPUT_DIR}/ca/ca.pem "
                     "-ca-key={OUTPUT_DIR}/ca/ca-key.pem "
                     "-config={TEMPLATE_DIR}/ca-config.json "
                     "-profile=kubernetes "
                     "-hostname=%(hostname)s,%(ip_address)s "
                     "%(template_path)s" % {
                         'hostname': hostname,
                         'ip_address': ip_address,
                         'template_path': '{WORKER_DIR}/%s_node-csr.json' % hostname}),
                write_output='{WORKER_DIR}/cfssl_gencert_node-%s.output' % hostname)

            self.run_command(
                cmd=("{BIN_DIR}/cfssljson -bare "
                     "-f {WORKER_DIR}/cfssl_gencert_node-%(hostname)s.output "
                     "-bare {WORKER_DIR}/%(hostname)s" % {'hostname': hostname}))


    def create_kubelet_kubeconfigs(self, node_type):
        """create kubeconfigs for specified node_type ."""
        for cur_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                self.config.get(node_type, 'prefix'),
                self.get_node_domain(),
                cur_index)
            logging.info('creating system:node kubeconfig for %s.', hostname)
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
                '--client-certificate={WORKER_DIR}/%(hostname)s.pem '
                '--client-key={WORKER_DIR}/%(hostname)s-key.pem '
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

    def create_kubeproxy_kubeconfigs(self):
        """create kube-proxy kubeconfigs."""
        logging.info('creating kubeproxy kubeconfigs.')
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
            '{BIN_DIR}/kubectl config set-credentials kube-proxy '
            '--client-certificate={PROXY_DIR}/kube-proxy.pem '
            '--client-key={PROXY_DIR}/kube-proxy-key.pem '
            '--embed-certs=true '
            '--kubeconfig={PROXY_DIR}/kube-proxy.kubeconfig')

        self.run_command(
            '{BIN_DIR}/kubectl config set-context default '
            '--cluster=%(cluster_name)s '
            '--user=kube-proxy '
            '--kubeconfig={PROXY_DIR}/kube-proxy.kubeconfig' % {
                'cluster_name': self.config.get('general', 'cluster_name')
                })

        self.run_command(
            '{BIN_DIR}/kubectl config use-context default '
            '--kubeconfig={PROXY_DIR}/kube-proxy.kubeconfig'
        )
        logging.info('finished creating kubeproxy kubeconfigs')

    def create_proxy_certs(self):
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
                 "{TEMPLATE_DIR}/kubernetes-csr.json" % ({
                     'hostname_arg': hostname_arg,
                     })),
            write_output='{TMP_DIR}/cfssl_gencert_api_server.output')

        self.run_command(
            cmd=('{BIN_DIR}/cfssljson -bare -f {TMP_DIR}/cfssl_gencert_api_server.output '
                 '{API_SERVER_DIR}/kubernetes')
            )
        logging.info("finished creating api server certificates")


    def deploy_etcd_certs(self, node_type):
        """copy etcd certificates to directory on host and restart etcd."""
        nodes = self.config.get(node_type, 'ip_addresses').split(',')
        remote_user = self.config.get(node_type, 'remote_user')

        logging.info('bootstraping etcd on %s nodes.', node_type)
        destination_dir = '/etc/ssl/certs/'

        for node_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                self.config.get(node_type, 'prefix'),
                self.get_node_domain(),
                node_index)

            cert_files = (
                '{CA_DIR}/ca.pem {ETCD_DIR}/%(hostname)s-etcd.pem '
                '{ETCD_DIR}/%(hostname)s-etcd-key.pem' % {
                    'hostname': hostname})

            logging.info('bootstraping etcd on %s.', hostname)

            self.scp_file(
                cert_files,
                remote_user,
                nodes[node_index],
                '~/'
            )

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                'sudo mkdir -p %s' % destination_dir,
            )

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                ('sudo cp ca.pem %(hostname)s-etcd.pem %(hostname)s-etcd-key.pem '
                 '%(destination_dir)s' % {
                     'hostname': hostname,
                     'destination_dir': destination_dir}))

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                ('sudo chown etcd:etcd %(destination_dir)s/ca.pem '
                 '%(destination_dir)s/%(hostname)s-etcd.pem '
                 '%(destination_dir)s/%(hostname)s-etcd-key.pem ' % {
                     'hostname': hostname,
                     'destination_dir': destination_dir}))

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                'sudo systemctl stop etcd-member.service',
                ignore_errors=True)

            self.run_command_via_ssh(
                remote_user,
                nodes[node_index],
                'sudo systemctl start --no-block etcd-member.service'
            )

    def bootstrap_control_plane_rbac(self):
        """bootstrap control plane kubernetes rbac configs."""

        files = ['kube_apiserver_to_kubelet_clusterrole.yaml',
                 'kube_apiserver_to_kubelet_clusterrolebinding.yaml']

        remote_host = self.config.get('controller',
                                      'ip_addresses').split(',')[0]
        for cur_file in files:
            self.scp_file(
                '{CONFIG_DIR}/' + cur_file,
                self.config.get('controller', 'remote_user'),
                remote_host,
                '~/')

            self.run_command_via_ssh(
                self.config.get('controller', 'remote_user'),
                remote_host,
                '%(install_dir)s/bin/kubectl apply -f %(config)s' % {
                    'install_dir': self.config.get('general',
                                                   'install_dir'),
                    'config': cur_file})

    def bootstrap_node(self, node_type):
        """bootstrap kubernetes workers."""
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
                'kube-proxy kubelet',
                'stop')
            self.install_node_binaries(
                hostname,
                nodes[node_index],
                remote_user)
            self.configure_node_kubeproxy(
                hostname,
                nodes[node_index],
                remote_user)
            self.configure_kubelet(node_type, hostname, nodes[node_index], remote_user)
            self.control_binaries(
                hostname,
                nodes[node_index],
                remote_user,
                'kube-proxy kubelet',
                'start')

    def install_node_binaries(self, hostname, remote_ip, remote_user):
        """install kubernetes and networking binaries on worker node."""
        logging.info('bootstraping kubernetes worker node %s at %s.',
                     hostname,
                     remote_ip)

        self.run_command_via_ssh(
            remote_user,
            remote_ip,
            'wget -q --show-progress --https-only --timestamping \
            https://github.com/containernetworking/plugins/releases/download/v0.6.0/cni-plugins-amd64-v0.6.0.tgz')

        self.run_command_via_ssh(
            remote_user,
            remote_ip,
            '''sudo mkdir -p \
            /opt/cni/bin \
            /var/lib/kubelet \
            /var/lib/kube-proxy \
            /var/lib/kubernetes \
            /var/run/kubernetes \
            %(install_dir)s/bin''' % {'install_dir': self.config.get(
                'general',
                'install_dir')})

        self.run_command_via_ssh(
            remote_user,
            remote_ip,
            'sudo tar -xvf cni-plugins-amd64-v0.6.0.tgz -C /opt/cni/bin/')

        kube_bins = ['kubectl', 'kubelet', 'kube-proxy']
        for cur_file in kube_bins:
            self.scp_file(
                '{BIN_DIR}/%s' % cur_file,
                remote_user,
                remote_ip,
                '~')

            self.run_command_via_ssh(
                remote_user,
                remote_ip,
                'sudo cp %(cur_file)s %(install_dir)s/bin/' % {
                    'cur_file': cur_file,
                    'install_dir': self.config.get('general', 'install_dir')
                }
            )
            self.run_command_via_ssh(
                remote_user,
                remote_ip,
                'sudo chmod +x %(install_dir)s/bin/%(cur_file)s' % {
                    'cur_file': cur_file,
                    'install_dir': self.config.get('general', 'install_dir'),
                }
            )



    def configure_kubelet(self, node_type, hostname, remote_ip, remote_user):
        """create kubelet configuration for node and install it on node."""
        logging.info('deploying kubelet to %s on %s.', hostname, remote_ip)


        self.run_command_via_ssh(
            remote_user,
            remote_ip,
            'sudo mkdir -p /var/lib/kubelet/')

        self.scp_file(
            '{WORKER_DIR}/%(hostname)s.kubeconfig' % {'hostname': hostname},
            remote_user,
            remote_ip,
            '~/')

        self.run_command_via_ssh(
            remote_user,
            remote_ip,
            'sudo cp %(hostname)s.kubeconfig /var/lib/kubelet/kubeconfig' % {
                'hostname': hostname
            }
        )

        template_vars = {
            'CLUSTER_DNS': self.config.get('general',
                                           'cluster_dns_ip_address'),
            'HOSTNAME': hostname,
            'INSTALL_DIR': self.config.get('general', 'install_dir')
        }

        self.write_template(
            '{TEMPLATE_DIR}/kubelet.service',
            '{WORKER_DIR}/%(worker_hostname)s.kubelet.service' % {
                'worker_hostname': hostname},
            template_vars)

        self.scp_file(
            '{WORKER_DIR}/%(worker_hostname)s.kubelet.service' % {
                'worker_hostname': hostname},
            remote_user,
            remote_ip,
            '~/')

        self.run_command_via_ssh(
            remote_user,
            remote_ip,
            'sudo cp %(worker_hostname)s.kubelet.service /etc/systemd/system/kubelet.service' % {
                'worker_hostname': hostname})


    def configure_node_kubeproxy(self, hostname, remote_ip, remote_user):
        """create kubeproxy configuration for worker and install it on node."""
        logging.info('deploying kube-proxy to %s on %s.', hostname, remote_ip)

        self.write_template(
            '{TEMPLATE_DIR}/kube-proxy.service',
            '{WORKER_DIR}/kube-proxy.service',
            {'CLUSTER_CIDR': self.config.get('general', 'cluster_cidr'),
             'INSTALL_DIR': self.config.get('general', 'install_dir')})

        self.scp_file(
            '{WORKER_DIR}/kube-proxy.service',
            remote_user,
            remote_ip,
            '~/')

        self.run_command_via_ssh(
            remote_user,
            remote_ip,
            'sudo cp kube-proxy.service /etc/systemd/system/')

        self.run_command_via_ssh(
            remote_user,
            remote_ip,
            'sudo mkdir -p /var/lib/kube-proxy/')


        self.scp_file(
            '{PROXY_DIR}/kube-proxy.kubeconfig',
            remote_user,
            remote_ip,
            '~/',
            )
        self.run_command_via_ssh(
            remote_user,
            remote_ip,
            'sudo cp kube-proxy.kubeconfig /var/lib/kube-proxy/kubeconfig')

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
             "--kubeconfig={ADMIN_DIR}/kubeconfig"))

        self.run_command(
            ("{BIN_DIR}/kubectl config set-context %(cluster_name)s "
             "--cluster=%(cluster_name)s "
             "--user=admin "
             "--kubeconfig={ADMIN_DIR}/kubeconfig" % {
                 'cluster_name': self.config.get('general', 'cluster_name')
             }
            ))

        self.run_command(
            ("{BIN_DIR}/kubectl config use-context %(cluster_name)s "
             "--kubeconfig={ADMIN_DIR}/kubeconfig" % {
                 'cluster_name': self.config.get('general', 'cluster_name')
                 }))

        logging.info("done creating admin kubeconfig for remote access.")

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

    def control_binaries(self, hostname, remote_ip, remote_user,
                         services, action=None):
        """control kubernetes binaries on a host."""


        if action == "stop":
            logging.info('stopping services %s on %s.', services, hostname)
            # NOTE: ignore_errors on stop here because there might be a situation
            # where this is the initial rollout, and there's nothing to stop.
            # still seems like a hack. would it make sense to check for binaries
            # existance first before stopping?

            self.run_command_via_ssh(
                remote_user,
                remote_ip,
                'sudo systemctl stop %s' % services,
                ignore_errors=True)

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

    def apply_taints(self, node_type):
        logging.info('applying node taints to %s nodes.' % node_type)

        for node_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(
                self.config.get(node_type, 'prefix'),
                self.get_node_domain(),
                node_index)

            logging.debug('applying node taint to %s.' % hostname)

            self.run_command(
                cmd=('{BIN_DIR}/kubectl --kubeconfig={ADMIN_DIR}/kubeconfig '
                     'taint nodes --overwrite %(hostname)s '
                     'node-role.kubernetes.io/master='':NoSchedule' % {
                         'hostname': hostname}))

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
