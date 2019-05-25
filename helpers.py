"""Helper functions as part of Kubify script."""

import ipaddress
import logging
import os

import jinja2


def hostname_with_index(hostname, domain, host_index):
    """return indexed fqdn."""
    hostname = '%(hostname)s%(host_index)d.%(domain)s' % ({
        'hostname': hostname,
        'domain': domain,
        'host_index': host_index})
    return hostname.lower()

def get_ip_from_range(host_index, cidr):
    """retrieve IP from range

    cidr: XXXX.XXX.XXX.XXX/YY network and netmask specification
    starting_ip: host_index of IP addresses in cider

    """
    network = ipaddress.ip_network(cidr)
    logging.debug("Computed Network: %s", network)
    hosts = [x.exploded for x in network.hosts()]

    logging.debug('Returning %s IP address from get_ip_from_range.', hosts[host_index])
    return hosts[host_index]


def render_template(template_file, template_vars):
    """Return jinja2 template with context vars filled in."""

    path, filename = os.path.split(template_file)
    rendered_template = jinja2.Environment(
        loader=jinja2.FileSystemLoader(path)
        ).get_template(filename).render(template_vars)
    logging.debug('rendered template: %s', rendered_template)
    return rendered_template
