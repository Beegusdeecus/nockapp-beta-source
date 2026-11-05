"""Installer-pinned connection route separate from a role's TLS identity.

The route resolves through the existing public-address-only connector. TLS still
authenticates host, using the installer-pinned CA and TLS1.3; it never substitutes
connect_host as the certificate name. No wire protocol or legacy endpoint change.
"""
import hashlib
import time

from policy import canonical, require
from ticket_transport_v2 import TicketRemote, endpoint as legacy_ticket_endpoint, _connect, DEADLINE
from ticket_refund_rpc_v1 import RefundRemote, endpoint as legacy_refund_endpoint

TICKET = 'nockapp-prepaid-service-routed-endpoint-v1'
REFUND = 'nockapp-refund-service-routed-endpoint-v1'


def _routed(value, *, refund):
    require(type(value) is dict and set(value) == {
        'profile', 'host', 'connect_host', 'port', 'service', 'offer_sha256'
    } | ({'policy_sha256'} if refund else set())
        and value['profile'] == (REFUND if refund else TICKET), 'ticket-routed-endpoint')
    legacy = {k: v for k, v in value.items() if k != 'connect_host'}
    legacy['profile'] = 'nockapp-refund-service-endpoint-v1' if refund else 'nockapp-prepaid-service-endpoint-v2'
    (legacy_refund_endpoint if refund else legacy_ticket_endpoint)(legacy)
    # Reuse the strict DNS-host/port parser for the route too. Runtime DNS
    # answers still undergo the unchanged global-unicast address checks.
    legacy_ticket_endpoint({'profile': 'nockapp-prepaid-service-endpoint-v2',
        'host': value['connect_host'], 'port': value['port'], 'service': 'payment',
        'offer_sha256': value['offer_sha256']})
    return value


def ticket_endpoint(value):
    if type(value) is dict and value.get('profile') == TICKET:
        return _routed(value, refund=False)
    return legacy_ticket_endpoint(value)


def refund_endpoint(value):
    if type(value) is dict and value.get('profile') == REFUND:
        return _routed(value, refund=True)
    return legacy_refund_endpoint(value)


def distinct_identities(endpoints):
    if any(v.get('profile') in (TICKET, REFUND) for v in endpoints):
        require(len({v['host'] for v in endpoints}) == len(endpoints),
            'ticket-routed-shared-TLS-identity')


class _Routing:
    def __init__(self, approved, context, *, dial=None):
        super().__init__(approved, context, dial=self._connect_route if dial is None else dial)

    def _connect_route(self):
        approved = self._endpoint(self.approved)
        require(hashlib.sha256(canonical(approved)).hexdigest() == self._approved_sha256,
            'ticket-endpoint-changed')
        return _connect({'host': approved['connect_host'], 'port': approved['port']},
            time.monotonic() + DEADLINE)


class RoutedTicketRemote(_Routing, TicketRemote):
    _endpoint = staticmethod(lambda value: _routed(value, refund=False))


class RoutedRefundRemote(_Routing, RefundRemote):
    _endpoint = staticmethod(lambda value: _routed(value, refund=True))


def ticket_remote(approved, context):
    value = ticket_endpoint(approved)
    return (RoutedTicketRemote if value['profile'] == TICKET else TicketRemote)(value, context)


def refund_remote(approved, context):
    value = refund_endpoint(approved)
    return (RoutedRefundRemote if value['profile'] == REFUND else RefundRemote)(value, context)
