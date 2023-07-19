# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring,redefined-outer-name

import logging
import os
import sys
import tempfile

import pytest
import salt.config
import salt.loader

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture(scope="session")
def tmpd():
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture(scope="session")
def opts(tmpd):
    opts = salt.config.minion_config(os.path.join(ROOT, "test/minion.yml"))
    opts["cachedir"] = os.path.join(tmpd, "cache")
    opts["pki_dir"] = os.path.join(tmpd, "pki")
    opts["module_dirs"] = [ROOT, os.path.join(ROOT, "test/fixtures")]

    grains = salt.loader.grains(opts)
    opts["grains"] = grains

    return opts


@pytest.fixture()
def utils(opts):
    return salt.loader.utils(opts)


@pytest.fixture()
def mods(opts, utils):
    return salt.loader.minion_mods(opts, utils=utils)


@pytest.fixture()
def serializers(opts):
    return salt.loader.serializers(opts)


@pytest.fixture()
def states(opts, mods, utils, serializers):
    loader = salt.loader.states(opts, mods, utils, serializers)
    loader._load_module("pki")  # pylint: disable=protected-access
    return loader

@pytest.fixture(autouse=True)
def debug_log_level(caplog):
    caplog.set_level(logging.DEBUG)
