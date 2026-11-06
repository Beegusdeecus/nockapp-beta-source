"""Trusted launcher: recovered/sealed service keys plus public TLS renewal.

Preserves original config/packet/authorities. No initializer, CA credential,
private file, original issuer material, permission changes or browser entrypoint.
Deployment profile/installer/frozen-package adoption remain explicit gates.
"""
import socket
from policy import canonical,require,Rejected
from ticket_backend_boot_v1 import validate,assemble,harden_process
from ticket_backend_resources_v1 import Resources,open_sealed
from ticket_host_tls_renewal_v1 import RenewingContext
from ticket_host_tls_delivery_v1 import PublicCertificates,CertificatePoller

def assemble_recovered(config,expected,body,directory,*,ticket_native,rpc,s3,
                    scratch_directory=None,origin=None,author_native=None,publication_budget_upgrade=None,publication_protocol=2,offer_overlay=None):
    harden_process();cfg=validate(config,expected)
    if publication_budget_upgrade is not None:
        from ticket_budget_upgrade_v1 import validate as validate_budget
        require(type(publication_budget_upgrade) is dict and set(publication_budget_upgrade)=={'plan','sha256'},'ticket-budget-envelope')
        validate_budget(publication_budget_upgrade['plan'],publication_budget_upgrade['sha256'],cfg)
    require(type(directory) is PublicCertificates,'ticket-renewing-boot-directory')
    # A bad/missing public update must not discard a still-valid embedded leaf.
    try:context=RenewingContext(cfg,expected,body)
    except Exception:context=None
    if context is None:
        try:context=RenewingContext(cfg,expected,body,certificate_der=directory.read(cfg['role']))
        except Exception:raise Rejected('ticket-renewing-boot-certificate-unavailable') from None
    poller=CertificatePoller(directory,cfg['role'],context);poller.refresh()
    context.current() # No application/journal initialization with expired TLS.
    read,write=socket.socketpair()
    try:
        data=canonical(context._body);require(len(data)<=65536,'ticket-renewing-boot-body')
        write.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,131072)
        require(write.getsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF)>=131072,'ticket-renewing-boot-buffer')
        write.settimeout(5);write.sendall(data);write.shutdown(socket.SHUT_WR)
        app,_,server=assemble(cfg,expected,read.fileno(),ticket_native=ticket_native,rpc=rpc,s3=s3,
            scratch_directory=scratch_directory,origin=origin,author_native=author_native,
            publication_protocol=publication_protocol,
            offer_overlay=offer_overlay,
            **({'publication_budget_upgrade':publication_budget_upgrade}if publication_budget_upgrade is not None else {}))
        return app,context,server,poller
    finally:read.close();write.close()

def assemble_sealed(config,expected,resources,envelope,directory,*,ticket_native,
                    scratch_directory=None,author_native=None,publication_budget_upgrade=None,publication_protocol=2,offer_overlay=None):
    cfg=validate(config,expected)
    if offer_overlay is not None:
        from ticket_offer_overlay_v1 import validate as overlay_validate
        require(type(offer_overlay)is dict and set(offer_overlay)=={'plan','sha256'},'ticket-overlay-envelope')
        overlay_validate(offer_overlay['plan'],offer_overlay['sha256'],cfg,expected)
    if publication_budget_upgrade is not None:
        from ticket_budget_upgrade_v1 import validate as validate_budget
        require(type(publication_budget_upgrade) is dict and set(publication_budget_upgrade)=={'plan','sha256'},'ticket-budget-envelope')
        validate_budget(publication_budget_upgrade['plan'],publication_budget_upgrade['sha256'],cfg)
    require(type(resources) is Resources and resources.backend_sha256==expected
        and resources.role==cfg['role'],'ticket-renewing-boot-resources')
    body=open_sealed(resources,envelope)
    return assemble_recovered(cfg,expected,body,directory,ticket_native=ticket_native,
        rpc=resources.rpc,s3=resources.s3,scratch_directory=scratch_directory,
        origin=resources.origin,author_native=author_native,publication_protocol=publication_protocol,offer_overlay=offer_overlay,
        **({'publication_budget_upgrade':publication_budget_upgrade}if publication_budget_upgrade is not None else {}))
