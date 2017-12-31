#!/usr/bin/env python

import argparse
import logging
import os
import shutil
import subprocess
import sys
import urllib

class KubeBuild:

    def __init__(self, cli_args):
        self.args = cli_args
        self.checkout_path = os.path.dirname(os.path.realpath(sys.argv[0]))
        self.bin_path = os.path.join(self.checkout_path, 'bin')
        logging.info('Checkout Path: %s, Bin Path: %s.',
                      self.checkout_path, self.bin_path)

    def get_bin_dir(self):
        return os.path.join(self.args.output_dir, 'bin')

    def build(self):
        self.create_output_dirs()
        self.download_tools()
        self.create_ca_cert_private_key()
        self.create_admin_client_cert()

    def run_bin_command(self, cmd, return_output=False,
                        cmd_stdin=None,  write_output=''):
        """given a command, run it from the bin directory of the checkout."""
        command_list = cmd.split()
        command_list[0] = os.path.join(self.args.output_dir,
                                       'bin',
                                       command_list[0])
        logging.info("command about to run: %s" % command_list)
        try:
            output = subprocess.check_output(
                command_list,
                stdin=cmd_stdin,
                )
        except subprocess.CalledProcessError as err:
            logging.fatal("Error in running %s. Error: %s", cmd, err)
            sys.exit(1)

        logging.info("command output: %s", output)

        if write_output:
            out_file = os.path.join(self.args.output_dir, write_output)
            logging.info("writing output to %s.", out_file)
            with open(out_file, 'w') as of:
                of.write(output)
            logging.info("done writing output to %s.", out_file)

        if return_output:
            return output


    def create_output_dirs(self):
        subdirs = ['admin', 'bin', 'ca', 'tmp']

        if not self.args.clear_output_dir and os.path.exists(self.args.output_dir):
            logging.fatal('output directory already exists, but you chose not to clear it out '
                          'first. are old configs still present that you still want to save?')
            sys.exit(1)

        if os.path.exists(self.args.output_dir):
            shutil.rmtree(self.args.output_dir)

        os.makedirs(self.args.output_dir)
        for current_dir in subdirs:
            os.makedirs(os.path.join(self.args.output_dir,
                                     current_dir))

    def download_tools(self):
        logging.info("downloading new set of binary tools")
        urllib.urlretrieve('https://pkg.cfssl.org/R1.2/cfssl_linux-amd64',
                           os.path.join(self.get_bin_dir(), 'cfssl'))
        os.chmod(os.path.join(self.get_bin_dir(), 'cfssl'), 0775)

        urllib.urlretrieve('https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64',
                           os.path.join(self.get_bin_dir(), 'cfssljson'))
        os.chmod(os.path.join(self.get_bin_dir(), 'cfssljson'), 0775)

        urllib.urlretrieve(
            'https://storage.googleapis.com/kubernetes-release/release/v%s/bin/linux/amd64/kubectl' % self.args.kube_ver,
            os.path.join(self.get_bin_dir(), 'kubectl'))
        os.chmod(os.path.join(self.get_bin_dir(), 'kubectl'), 0775)
        logging.info("done downloading tools")

    def create_ca_cert_private_key(self):
        """create ca cert and private key."""
        self.run_bin_command(
            cmd="cfssl gencert -initca %s/ca-csr.json" % (
                os.path.join(self.checkout_path,'templates')),
            write_output='tmp/cfssl_initca.output')

        self.run_bin_command(
            cmd='cfssljson -bare -f %s %s/ca' % (
                os.path.join(self.args.output_dir, 'tmp',
                             'cfssl_initca.output'),
                os.path.join(self.args.output_dir, 'ca')
                )
            )

    def create_admin_client_cert(self):
        """create admin client certificate"""
        self.run_bin_command(
            cmd=("cfssl gencert -ca=%(output_dir)s/ca/ca.pem "
                 "-ca-key=%(output_dir)s/ca/ca-key.pem "
                 "-config=%(template_dir)s/ca-config.json "
                 "-profile=kubernetes %(template_dir)s/admin-csr.json" %
                 {'template_dir': os.path.join(self.checkout_path,
                                               'templates'),
                  'output_dir': self.args.output_dir}
                 ),
            write_output='tmp/cfssl_gencert_admin.output')

        self.run_bin_command(
            cmd='cfssljson -bare -f %s %s/admin' % (
                os.path.join(self.args.output_dir,
                             'tmp', 'cfssl_gencert_admin.output'),
                os.path.join(self.args.output_dir, 'admin')
                ),
            )


def main():
    parser = argparse.ArgumentParser(
        description='Install Kubernetes, the hard way.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--kube_ver',
                        dest='kube_ver',
                        help='kubernetes version',
                        default='1.9.0')
    parser.add_argument('--output_dir',
                        dest='output_dir',
                        help=('base directory where generated configs '
                              'will be stored.'))
    parser.add_argument('--clear_output_dir',
                        dest='clear_output_dir',
                        action='store_true',
                        help='if true, clear the output directory before generating configs')

    args = parser.parse_args()
    logging.basicConfig(
        format='%(asctime)-15s %(message)s',
        level=logging.INFO)
    k8s = KubeBuild(args)
    k8s.build()


if __name__ == '__main__':
    main()
