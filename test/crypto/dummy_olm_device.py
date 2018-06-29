"""Tests can import OlmDevice from here, and know it won't try to use a database."""

from matrix_client.crypto.olm_device import OlmDevice as BaseOlmDevice


class DummyStore(object):
    def __init__(*args, **kw): pass

    def nop(*args, **kw): pass

    def __getattr__(self, _): return self.nop


class OlmDevice(BaseOlmDevice):

    def __init__(self, *args, **kw):
        super(OlmDevice, self).__init__(*args, Store=DummyStore, **kw)
