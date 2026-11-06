"""Isolated pinned compiler target for fixed payment-receipt contract only."""
import json
import subprocess
from pathlib import Path
from base_evm import TOOLS
from permissionless_contracts import SETTINGS
from policy import require


def build():
    source=Path(__file__).resolve().parent/'base/contracts/PrepaidTicketPacks.sol'
    request={'language':'Solidity','sources':{'contracts/PrepaidTicketPacks.sol':{'content':source.read_text()}},'settings':SETTINGS}
    p=subprocess.run([str(TOOLS/'solc-0.8.30'),'--standard-json'],input=json.dumps(request).encode(),
        capture_output=True,timeout=30,check=True)
    result=json.loads(p.stdout)
    require(not any(e['severity']=='error' for e in result.get('errors',[])),'ticket-purchase-build')
    return result['contracts']['contracts/PrepaidTicketPacks.sol']['PrepaidTicketPacks']
