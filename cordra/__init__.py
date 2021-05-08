""" This is a simple Python library for interacting with the REST interface of an instance of Cordra.
"""

# Set up requests and turn off warnings
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from .cordra import CordraObject, CordraClient


def get_version():
    """Get the version of the code from egg_info.
    Returns:
      the package version number
    """
    from pkg_resources import get_distribution, DistributionNotFound

    try:
        version = get_distribution(
            __name__.split(".")[0]
        ).version  # pylint: disable=no-member
    except DistributionNotFound:  # pragma: no cover
        version = "unknown, try running `python setup.py egg_info`"

    return version


def test():
    import pytest

    path = __file__.replace("__init__.py", "")
    pytest.main(args=[path, "--doctest-modules"])


__version__ = get_version()

__all__ = ["__version__", "CordraObject", "CordraClient", "Token"]
