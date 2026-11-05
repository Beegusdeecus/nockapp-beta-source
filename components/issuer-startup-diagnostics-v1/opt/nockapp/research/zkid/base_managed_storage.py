"""Managed immutable ciphertext objects and CAS journal head over fixed AWS SDK.

The measured service supplies the authenticated fixed-host DynamoDB client and
least-privilege table/namespace. No ambient credentials, URLs, reset/delete,
private plaintext, table creation or caller-selected authority is exposed.
Actual IAM/cloud acceptance remains separate from local transaction fixtures.
"""
import hashlib
import re

from policy import Rejected,canonical,hex_string,require,strict_json
from domain_authority import _conflict

OBJECT_LIMIT=262144+28
CHUNK=192*1024
JOURNAL_LIMIT=16*1024*1024
MAX_CHUNKS=(JOURNAL_LIMIT+CHUNK-1)//CHUNK
PROFILE='nockapp-base-managed-journal-head-v1'


class DynamoObjects:
    def __init__(self,client,table,namespace):
        require(type(table) is str and re.fullmatch(r'[A-Za-z0-9_.-]{3,255}',table),'base-storage-table')
        hex_string(namespace,64);require(any(bytes.fromhex(namespace)),'base-storage-namespace')
        self.client,self.table,self.namespace=client,table,namespace

    def key(self,suffix):return {'id':{'S':self.namespace+':action:base:'+suffix}}

    def _get(self,suffix):
        try:
            response=self.client.get_item(TableName=self.table,Key=self.key(suffix),ConsistentRead=True)
            require(type(response) is dict,'base-storage-response')
            return response.get('Item')
        except Exception:raise Rejected('base-storage-unavailable') from None

    def get(self,digest):
        require(type(digest) is str and digest.startswith('0x'),'base-storage-digest');hex_string(digest[2:],64)
        item=self._get('object:'+digest[2:])
        require(type(item) is dict and set(item)=={'id','data'} and item['id']==self.key('object:'+digest[2:])['id']
            and type(item['data']) is dict and set(item['data'])=={'B'},'base-storage-missing')
        data=item['data']['B']
        require(type(data) is bytes and 0<len(data)<=OBJECT_LIMIT
            and '0x'+hashlib.sha256(data).hexdigest()==digest,'base-storage-digest')
        return data

    def put(self,data):
        require(type(data) is bytes and 0<len(data)<=OBJECT_LIMIT,'base-storage-size')
        digest='0x'+hashlib.sha256(data).hexdigest();key=self.key('object:'+digest[2:])
        try:
            self.client.put_item(TableName=self.table,Item={**key,'data':{'B':data}},
                ConditionExpression='attribute_not_exists(#id)',ExpressionAttributeNames={'#id':'id'})
        except Exception:
            # An existing immutable object or a lost Put reply can both be
            # resolved by a consistent read, never an unconditional overwrite.
            require(self.get(digest)==data,'base-storage-conflict')
        return digest


class DynamoJournalAnchor:
    """A trusted managed CAS head prevents parent-file replay across boots.

    Chunks are durable before committing their manifest. Orphan chunks are safe;
    a commitment never substitutes for unavailable ciphertext. No rollback or
    reset operation is available. Retention/quotas and actual IAM denial of
    non-workload writers must be checked during live deployment.
    """
    production_antirollback=False

    def __init__(self,objects,signer_address):
        require(type(signer_address) is str and signer_address.startswith('0x'),'base-journal-address')
        hex_string(signer_address[2:],40)
        self.objects=objects;self.suffix='journal:'+signer_address[2:]

    def _head(self):
        item=self.objects._get(self.suffix)
        if item is None:return None,None
        require(type(item) is dict and set(item)=={'id','revision','body'}
            and item['id']==self.objects.key(self.suffix)['id']
            and type(item['revision']) is dict and set(item['revision'])=={'N'}
            and type(item['body']) is dict and set(item['body'])=={'B'},'base-journal-head')
        body=strict_json(item['body']['B'])
        require(set(body)=={'profile','revision','digest','bytes','chunks'} and body['profile']==PROFILE
            and type(body['revision']) is int and 0<=body['revision']<2**53
            and item['revision']=={'N':str(body['revision'])} and canonical(body)==item['body']['B']
            and type(body['bytes']) is int and 28<body['bytes']<=JOURNAL_LIMIT
            and type(body['chunks']) is list and 0<len(body['chunks'])<=MAX_CHUNKS,'base-journal-head')
        require(len(body['chunks'])==(body['bytes']+CHUNK-1)//CHUNK,'base-journal-head')
        for digest in [body['digest'],*body['chunks']]:
            require(type(digest) is str and digest.startswith('0x'),'base-journal-head');hex_string(digest[2:],64)
        return body['revision'],body

    def read(self):
        revision,body=self._head()
        if body is None:return None,None
        parts=[self.objects.get(digest) for digest in body['chunks']]
        require(all(len(part)==CHUNK for part in parts[:-1]),'base-journal-chunks')
        data=b''.join(parts)
        require(len(data)==body['bytes'] and '0x'+hashlib.sha256(data).hexdigest()==body['digest'],
            'base-journal-chunks')
        return revision,data

    def compare_exchange(self,expected,envelope):
        require(expected is None or type(expected) is int and 0<=expected<2**53-1,'base-journal-revision')
        require(type(envelope) is bytes and 28<len(envelope)<=JOURNAL_LIMIT,'base-journal-size')
        chunks=[self.objects.put(envelope[i:i+CHUNK]) for i in range(0,len(envelope),CHUNK)]
        revision=0 if expected is None else expected+1
        body={'profile':PROFILE,'revision':revision,'digest':'0x'+hashlib.sha256(envelope).hexdigest(),
            'bytes':len(envelope),'chunks':chunks}
        item={**self.objects.key(self.suffix),'revision':{'N':str(revision)},'body':{'B':canonical(body)}}
        parameters={'TableName':self.objects.table,'Item':item,'ExpressionAttributeNames':{'#id':'id'}}
        if expected is None:parameters['ConditionExpression']='attribute_not_exists(#id)'
        else:
            parameters.update(ConditionExpression='attribute_exists(#id) AND #revision = :expected',
                ExpressionAttributeNames={'#id':'id','#revision':'revision'},
                ExpressionAttributeValues={':expected':{'N':str(expected)}})
        try:self.objects.client.put_item(**parameters)
        except Exception as error:
            observed_revision,observed=self._head()
            if observed_revision==revision and observed==body:return revision
            raise Rejected('base-journal-conflict' if _conflict(error) or observed_revision!=expected
                else 'base-storage-unavailable') from None
        return revision
