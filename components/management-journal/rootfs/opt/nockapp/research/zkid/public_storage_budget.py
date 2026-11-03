"""Managed pre-I/O resource reservations for the measured public storage service.

Explicit provisioner initialization only; no boot reset/refund. Counts OUR S3
calls, including uncertain/failed requests and full permitted response payloads.
This is not a monetary cap, billing observation, traffic meter for independent
public readers, or proof that lifecycle/retention/IAM policies exist in AWS.
"""
import copy
import secrets

from domain_authority import DynamoPublicStore,_number
from policy import Rejected,canonical,digest,hex_string,require
from public_bundle import MAX_BYTES

RESOURCES=('put_requests','get_requests','upload_bytes','download_bytes','retained_byte_seconds')
MAX=2**53-1


def limits(value):
    require(type(value) is dict and set(value)==set(RESOURCES) and
        all(type(v) is int and 0<v<=MAX for v in value.values()),'public-storage-budget-limits')
    return copy.deepcopy(value)


def scope(identity,storage,policy):
    """New policy/replicas require explicit provisioning, not automatic new funds."""
    limits(policy)
    return digest({'profile':'nockapp-public-storage-budget-v1','chain':identity['chain_id'],
        'contract':identity['contract'],'application':identity['application'],
        'issuer':identity['definition_hash'],'storage':{k:storage[k] for k in ('replicas','retention_seconds')},'limits':policy})


class DynamoStorageBudget(DynamoPublicStore):
    max_object_bytes=MAX_BYTES
    def __init__(self,client,table,namespace,context,policy,retention_seconds):
        super().__init__(client,table,namespace);hex_string(context,64)
        require(type(retention_seconds) is int and 90*86400<=retention_seconds<=365*86400,'public-storage-budget-retention')
        self.context=context;self.limits=limits(policy);self.retention_seconds=retention_seconds
        self.prefix='action:public-storage:'+context+':'

    def _counter(self,name):return self.key(self.prefix+'counter:'+name)

    def initialize(self):
        """Provisioner only; never called by runtime boot or any public RPC."""
        self._write([{'Put':{'TableName':self.table,'Item':{**self._counter(name),
            'scope':{'S':self.context},'cap':{'N':str(self.limits[name])},'spent':{'N':'0'}},
            'ConditionExpression':'attribute_not_exists(#id)','ExpressionAttributeNames':{'#id':'id'}}}
            for name in RESOURCES],'public-storage-budget-already-initialized')

    def summary(self):
        # Transactional read gives one coherent snapshot of all resource caps.
        try:response=self._client.transact_get_items(TransactItems=[
            {'Get':{'TableName':self.table,'Key':self._counter(name)}} for name in RESOURCES])
        except Exception:raise Rejected('public-storage-budget-unavailable') from None
        require(type(response) is dict and type(response.get('Responses')) is list
            and len(response['Responses'])==len(RESOURCES),'public-storage-budget-state')
        spent={}
        for name,row in zip(RESOURCES,response['Responses']):
            item=row.get('Item') if type(row) is dict and set(row)=={'Item'} else None
            require(type(item) is dict and set(item)=={'id','scope','cap','spent'}
                and item['id']==self._counter(name)['id'] and item['scope']=={'S':self.context}
                and _number(item['cap'])==self.limits[name],'public-storage-budget-state')
            spent[name]=_number(item['spent']);require(spent[name]<=self.limits[name],'public-storage-budget-state')
        return {'scope':self.context,'limits':copy.deepcopy(self.limits),'reserved':spent,
            'billing_observed':False,'independent_reader_traffic_included':False}

    def reserve(self,method,upload_bytes,response_limit):
        require(method in ('GET','PUT') and type(upload_bytes) is int and 0<=upload_bytes<=self.max_object_bytes
            and type(response_limit) is int and 0<response_limit<=self.max_object_bytes
            and (method=='PUT' or upload_bytes==0),'public-storage-budget-request')
        amounts={name:0 for name in RESOURCES}
        amounts['put_requests' if method=='PUT' else 'get_requests']=1
        amounts.update(upload_bytes=upload_bytes,download_bytes=response_limit,
            retained_byte_seconds=upload_bytes*self.retention_seconds)
        require(all(amount<=self.limits[name] for name,amount in amounts.items()),'public-storage-budget-exhausted')
        # Validate the stored state before an update, including missing/negative
        # counters. The atomic conditions still prevent concurrent overspending.
        self.summary()
        request=secrets.token_hex(16)
        items=[{'Put':{'TableName':self.table,'Item':{**self.key(self.prefix+'charge:'+request),
            'scope':{'S':self.context},'resources':{'B':canonical(amounts)}},
            'ConditionExpression':'attribute_not_exists(#id)','ExpressionAttributeNames':{'#id':'id'}}}]
        for name,cost in amounts.items():
            if not cost:continue
            items.append({'Update':{'TableName':self.table,'Key':self._counter(name),
                'UpdateExpression':'SET #spent = #spent + :cost',
                'ConditionExpression':'attribute_exists(#id) AND #scope = :scope AND #cap = :cap AND #spent <= :max',
                'ExpressionAttributeNames':{'#id':'id','#scope':'scope','#cap':'cap','#spent':'spent'},
                'ExpressionAttributeValues':{':scope':{'S':self.context},':cost':{'N':str(cost)},
                    ':cap':{'N':str(self.limits[name])},':max':{'N':str(self.limits[name]-cost)}}}})
        # Lost commit replies burn a reservation and fail closed, before S3
        # dialing. A later attempt gets a NEW charge; no uncertain refund.
        self._write(items,'public-storage-budget-exhausted')
