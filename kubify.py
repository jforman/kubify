#!/usr/bin/env python

import argparse
import logging
import os
import shutil
import sys
import urllib

class KubeBuild:

    def __init__(self, cli_args):
        self.args = cli_args

    def get_bin_dir(self):
        return os.path.join(self.args.output_dir, 'bin')

    def build(self):
        self.create_output_dirs()
        self.download_tools()

    def create_output_dirs(self):
        subdirs = ['bin']

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
        print "foo: %s" % os.path.join(self.get_bin_dir(), 'kubectl')
        urllib.urlretrieve('https://pkg.cfssl.org/R1.2/cfssl_linux-amd64',
                           os.path.join(self.get_bin_dir(), 'cfssl'))
        os.chmod(os.path.join(self.get_bin_dir(), 'cfssl'), 0775)
        urllib.urlretrieve('https://pkg.cfssl.org/R1.2/cfssljson_linuxn-amd64',
                           os.path.join(self.get_bin_dir(), 'cfssljson'))
        os.chmod(os.path.join(self.get_bin_dir(), 'cfssljson'), 0775)
        urllib.urlretrieve('https://storage.googleapis.com/kubernetes-release/release/v%s/bin/linux/amd64/kubectl' % self.args.kube_ver,
                          os.path.join(self.get_bin_dir(), 'kubectl'))
        os.chmod(os.path.join(self.get_bin_dir(), 'kubectl'), 0775)        


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
    k8s = KubeBuild(args)
    k8s.build()


if __name__ == '__main__':
    main()
