"""Helper functions as part of Kubify script."""

import ipaddress
import logging
import os

import jinja2


def render_template(template_file, template_vars):
    """Return jinja2 template with context vars filled in."""

    path, filename = os.path.split(template_file)
    rendered_template = jinja2.Environment(
        loader=jinja2.FileSystemLoader(path)
        ).get_template(filename).render(template_vars)
    logging.debug('rendered template: %s', rendered_template)
    return rendered_template
