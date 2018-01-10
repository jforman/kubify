#!/usr/bin/env python

import argparse
import ConfigParser
import logging
import os
import shutil
import string
import subprocess
import sys
import urllib

import helpers

class KubeBuild:

    def __init__(self, cli_args):
        self.args = cli_args
        self.checkout_path = os.path.dirname(os.path.realpath(sys.argv[0]))

        self.config = ConfigParser.SafeConfigParser()
        self.config.read(self.args.config)

        logging.debug('Checkout Path: %s, Output Dir: %s',
                      self.checkout_path, self.args.output_dir)

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
            '{ADMIN_DIR}': os.path.join(path_dict['{OUTPUT_DIR}'], 'admin'),
            '{API_SERVER_DIR}': os.path.join(path_dict['{OUTPUT_DIR}'], 'api_server'),
            '{BIN_DIR}': os.path.join(path_dict['{OUTPUT_DIR}'], 'bin'),
            '{CA_DIR}': os.path.join(path_dict['{OUTPUT_DIR}'], 'ca'),
            '{PROXY_DIR}': os.path.join(path_dict['{OUTPUT_DIR}'], 'proxy'),
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


    def build(self):
        """main build sequencer function."""
        self.create_output_dirs()
        self.download_tools()
        self.create_ca_cert_private_key()
        self.create_admin_client_cert()
        self.create_worker_certs()
        self.create_proxy_certs()
        self.create_api_server_cert()
        self.deploy_certs('controller')
        self.deploy_certs('worker')

    def scp_file(self, local_path, remote_user, remote_host, remote_path):
        """copy the local file to the remote destination."""
        ssh_args = "-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
        self.run_command(
            "scp %(ssh_args)s %(local_path)s "
            "%(remote_user)s@%(remote_host)s:%(remote_path)s" % {
                'ssh_args': ssh_args,
                'local_path': local_path,
                'remote_user': remote_user,
                'remote_host': remote_host,
                'remote_path': remote_path
            }
        )


    def deploy_certs(self, node_type):
        """copy the certificates to kubernetes controller nodes."""
        nodes = self.config.get(node_type, 'ip_addresses').split(',')
        remote_user = self.config.get(node_type, 'remote_user')
        prefix = self.config.get(node_type, 'prefix')

        logging.debug('deploying %s certificates.', node_type)
        for node_index in range(0, self.get_node_count(node_type)):
            hostname = helpers.hostname_with_index(prefix, node_index)
            logging.debug('deploying %s certificates to %s.', node_type,
                          hostname)
            if node_type == 'worker':
                pem_files = ("{CA_DIR}/ca.pem {WORKER_DIR}/%(hostname)s.pem "
                             "{WORKER_DIR}/%(hostname)s-key.pem " % {
                                 'hostname': hostname})
            elif node_type == 'controller':
                pem_files = ("{CA_DIR}/ca.pem {CA_DIR}/ca-key.pem "
                             "{API_SERVER_DIR}/kubernetes-key.pem "
                             "{API_SERVER_DIR}/kubernetes.pem ")

            self.scp_file(
                pem_files,
                remote_user,
                nodes[node_index],
                '~/')


    def run_command(self, cmd, return_output=False,
                    cmd_stdin=None,  write_output=''):
        """given a command, translate needed paths and run it."""
        command_list = self.translate_path(cmd).split()

        if self.args.dry_run:
            logging.info('DRYRUN: would have run %s.', command_list)
        else:
            try:
                logging.debug('running %s', command_list)
                output = subprocess.check_output(
                    command_list,
                    stdin=cmd_stdin,
                    )
                logging.debug("command output: %s", output)
            except subprocess.CalledProcessError as err:
                logging.fatal("Error in running %s. Error: %s", command_list,
                              err)
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
        subdirs = ['admin', 'api_server', 'bin', 'ca',
                   'proxy', 'tmp', 'workers']

        if (
            not self.args.clear_output_dir and
            os.path.exists(self.args.output_dir) and
            not self.args.dry_run
            ):
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
        files_to_get = {
            'https://pkg.cfssl.org/R1.2/cfssl_linux-amd64':
            self.translate_path('{BIN_DIR}/cfssl'),
            'https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64':
            self.translate_path('{BIN_DIR}/cfssljson'),
            'https://storage.googleapis.com/kubernetes-release/release/v%s/bin/linux/amd64/kubectl' % self.args.kube_ver:
            self.translate_path('{BIN_DIR}/kubectl'),
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


    def create_worker_certs(self):
        """create certificates for kubernetes workers."""
        for cur_index in range(0, self.get_node_count('worker')):
            logging.info('creating csr json template for worker %d.',
                          cur_index)
            worker_hostname = helpers.hostname_with_index(
                self.config.get('worker', 'prefix'),
                cur_index)
            ip_address = self.get_node_ip_addresses('worker')[cur_index]
            logging.debug('Hostname: %s, IP Address: %s.',
                          worker_hostname, ip_address)

            template_vars = {
                'instance': worker_hostname,
            }
            worker_json = helpers.render_template(
                self.translate_path('{TEMPLATE_DIR}/worker-csr.json'),
                template_vars)

            template_path = self.translate_path(
                '{WORKER_DIR}/%s_worker-csr.json' % worker_hostname)

            if self.args.dry_run:
                logging.info('DRYRUN: would have written worker csr json '
                             'template to %s.', template_path)
            else:
                with open(template_path, 'w') as tp:
                    tp.write(worker_json)

            logging.info('creating worker certificate for host %s',
                        worker_hostname)
            self.run_command(
                cmd=("{BIN_DIR}/cfssl gencert -ca={OUTPUT_DIR}/ca/ca.pem "
                     "-ca-key={OUTPUT_DIR}/ca/ca-key.pem "
                     "-config={TEMPLATE_DIR}/ca-config.json "
                     "-profile=kubernetes "
                     "-hostname=%(worker_hostname)s,%(ip_address)s "
                     "%(template_path)s" % {
                        'worker_hostname': worker_hostname,
                        'ip_address': ip_address,
                        'template_path': template_path,}),
                write_output='{WORKER_DIR}/cfssl_gencert_worker-%s.output' % worker_hostname)

            self.run_command(
                cmd=("{BIN_DIR}/cfssljson -bare "
                     "-f {WORKER_DIR}/cfssl_gencert_worker-%s.output "
                     "-bare {WORKER_DIR}/%s" % (worker_hostname, worker_hostname))
            )


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

        self.run_command(
            cmd=("{BIN_DIR}/cfssl gencert -ca={OUTPUT_DIR}/ca/ca.pem "
                 "-ca-key={OUTPUT_DIR}/ca/ca-key.pem "
                 "-config={TEMPLATE_DIR}/ca-config.json "
                 "-hostname=%(controller_addresses)s,%(api_server_ip_address)s,127.0.0.1,kubernetes.default "
                 "-profile=kubernetes "
                 "{TEMPLATE_DIR}/kubernetes-csr.json" % ({
                     'controller_addresses': controller_addresses,
                     'api_server_ip_address': self.config.get(
                       'general',
                       'api_server_ip_address')
                     }
                 )),
            write_output='{TMP_DIR}/cfssl_gencert_api_server.output')

        self.run_command(
            cmd=('{BIN_DIR}/cfssljson -bare -f {TMP_DIR}/cfssl_gencert_api_server.output '
                 '{API_SERVER_DIR}/kubernetes')
            )
        logging.info("finished creating api server certificates")



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
        log_level=logging.DEBUG
    else:
        log_level=logging.INFO
    logging.basicConfig(
        format='%(asctime)-10s %(filename)s:%(lineno)d %(levelname)s %(message)s',
        level=log_level)

    if args.config is None:
        logging.critical('required config file not defined. must be '
                         'with --config')
        sys.exit(1)

    k8s = KubeBuild(args)
    k8s.build()


if __name__ == '__main__':
    main()