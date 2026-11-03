"""Versioned RoleServer integration with checked TLS context per new handshake.

Wire/application/recovery/rate/drain behavior is inherited unchanged from v1.
Only an exact trusted RenewingContext and its bounded public poller are accepted.
Not wired into old deployment profiles or installed services automatically.
"""
from policy import require
from ticket_server_v1 import RoleServer
from ticket_host_tls_renewal_v1 import RenewingContext
from ticket_host_tls_delivery_v1 import CertificatePoller

class RenewingRoleServer(RoleServer):
    @classmethod
    def from_config(cls,application,context,listener,value,pin,*,poller=None):
        require(poller is None or type(poller) is CertificatePoller and poller.context is context,
            'ticket-server-renewal-poller')
        server=super().from_config(application,context,listener,value,pin)
        server._poller=poller;return server
    def __init__(self,application,context,listener,limits,*,poller=None):
        require(type(context) is RenewingContext and context._config['role']==application.service
            and context._config['offer_sha256']==application.offer.hash,'ticket-server-renewal-scope')
        require(poller is None or type(poller) is CertificatePoller and poller.context is context,
            'ticket-server-renewal-poller')
        self._renewing=context;self._poller=poller;self._constructing=True
        try:super().__init__(application,context.current(),listener,limits)
        finally:self._constructing=False
    @property
    def context(self):
        # v1 reads self.context inside its bounded, tracked handshake path.
        return self._renewing.current()
    @context.setter
    def context(self,value):
        require(self._constructing and value is self._renewing.current(),'ticket-server-static-context-forbidden')
    def _recover(self):
        if self._poller is not None:self._poller.refresh()
        super()._recover()
    def snapshot(self):
        value=super().snapshot()
        try:self._renewing.current();value['tls_usable']=True
        except Exception:value['tls_usable']=False
        return value
    def run(self,stop,ready=None):
        def checked_ready(value):
            self._renewing.current()
            if ready is not None:ready(value)
        return super().run(stop,checked_ready)
