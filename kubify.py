#!/usr/bin/env python3

import argparse
import logging
import os
import shutil
import string
import subprocess
import sys
import urllib

class KubeBuild:

    def __init__(self, cli_args):
        self.args = cli_args
        self.checkout_path = os.path.dirname(os.path.realpath(sys.argv[0]))
        logging.info('Checkout Path: %s, Output Dir: %s',
                      self.checkout_path, self.args.output_dir)


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
            '{BIN_DIR}': os.path.join(path_dict['{OUTPUT_DIR}'], 'bin'),
            '{CA_DIR}': os.path.join(path_dict['{OUTPUT_DIR}'], 'ca'),
            '{TEMPLATE_DIR}': os.path.join(path_dict['{CHECKOUT_DIR}'],
                                           'templates'),
            '{TMP_DIR}': os.path.join(path_dict['{OUTPUT_DIR}'], 'tmp')

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


    def run_bin_command(self, cmd, return_output=False,
                        cmd_stdin=None,  write_output=''):
        """given a command, run it from the bin directory of the checkout."""
        command_list = self.translate_path(cmd).split()
        command_list[0] = os.path.join(self.args.output_dir,
                                       'bin',
                                       self.translate_path(command_list[0]))
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
                logging.fatal("Error in running %s. Error: %s", cmd, err)
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
        subdirs = ['admin', 'bin', 'ca', 'tmp', 'workers']

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
        self.run_bin_command(
            cmd="cfssl gencert -initca {TEMPLATE_DIR}/ca-csr.json",
            write_output='{TMP_DIR}/cfssl_initca.output')
        self.run_bin_command(
            cmd='cfssljson -bare -f {TMP_DIR}/cfssl_initca.output {CA_DIR}/ca')
        logging.info("finished creating ca certificates")


    def create_admin_client_cert(self):
        """create admin client certificate"""
        logging.info("beginning to create admin client certificates")
        self.run_bin_command(
            cmd=("cfssl gencert -ca={OUTPUT_DIR}/ca/ca.pem "
                 "-ca-key={OUTPUT_DIR}/ca/ca-key.pem "
                 "-config={TEMPLATE_DIR}/ca-config.json "
                 "-profile=kubernetes {TEMPLATE_DIR}/admin-csr.json"),
            write_output='{TMP_DIR}/cfssl_gencert_admin.output')

        self.run_bin_command(
            cmd=('cfssljson -bare -f {TMP_DIR}/cfssl_gencert_admin.output '
                 '{ADMIN_DIR}/admin')
            )
        logging.info("finished creating admin client certificates")


def main():
    """main for Kubify script."""
    parser = argparse.ArgumentParser(
        description='Install Kubernetes, the hard way.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
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
    parser.add_argument('--clear_output_dir',
                        dest='clear_output_dir',
                        action='store_true',
                        help='if true, clear the output directory before generating configs')

    args = parser.parse_args()

    if args.debug:
        log_level=logging.DEBUG
    else:
        log_level=logging.INFO
    logging.basicConfig(
        format='%(asctime)-10s %(filename)s:%(lineno)d %(levelname)s %(message)s',
        level=log_level)
    k8s = KubeBuild(args)
    k8s.build()


if __name__ == '__main__':
    main()
