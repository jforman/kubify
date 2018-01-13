# Helper functions as part of Kubify script

import ipaddress
import logging
import os

import jinja2


def hostname_with_index(hostname, domain, host_index):
    return '%(hostname)s%(host_index)d.%(domain)s' % ({
        'hostname': hostname,
        'domain': domain,
        'host_index': host_index})

def get_ip_from_range(host_index, starting_ip, netmask):
    """retrieve IP from range

    host_index: what number host in the cluster is this. zero-indexed.
    starting_ip: beginning IP in the cluster group.
    netmask: netmask for the starting_ip's network.

    If only one host, return IP address.
    If more than one, we need to calculate which IP of set to return.
    """
    if host_index == 0:
        return starting_ip

    network = ipaddress.ip_network(
            unicode('%s/%s' % (
                starting_ip,
                netmask)),
            strict=False)
    logging.debug("Computed Network: %s", network)
    hosts = [x.exploded for x in network.hosts()]
    host_start_index = hosts.index(starting_ip)
    logging.debug("Host start index: %s.", host_start_index)

    # Subtract one from the list because the list is
    # zero-indexed, but the cluster index is not.
    ip_address = hosts[host_start_index+host_index]
    logging.debug("Generated IP address: %s", ip_address)
    return ip_address

def render_template(template_file, template_vars):
    """Return jinja2 template with context vars filled in."""

    path, filename = os.path.split(template_file)
    rendered_template = jinja2.Environment(
        loader=jinja2.FileSystemLoader(path)
        ).get_template(filename).render(template_vars)
    logging.debug('rendered template: %s', rendered_template)
    return rendered_template
