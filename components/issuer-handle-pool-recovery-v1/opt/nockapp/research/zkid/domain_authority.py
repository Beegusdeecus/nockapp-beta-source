"""Composite managed state transactions, with separate issuer/verifier roles.

No table, role, credential or SDK client is created here. The client must be
the measured fixed-host authenticated AWS transport. Deployment/IAM acceptance
is still required; fake transactions do not prove production anti-rollback.
"""
import re

from budget import CAP_MICRO_USD, PER_REQUEST_MICRO_USD, OPERATIONS
from domain_pipeline import PROFILE, definition_hash
from domain_state import LIMIT
from policy import Rejected, canonical, digest, hex_string, require, strict_json, timestamp

MAX_REVISION = 2**53-1


def _number(value):
    require(type(value) is dict and set(value) == {'N'} and type(value['N']) is str
            and re.fullmatch(r'0|[1-9][0-9]{0,15}',value['N']),'registry-number')
    result=int(value['N']);require(result <= MAX_REVISION,'registry-number');return result


def _conflict(error):
    response=getattr(error,'response',{})
    if type(response) is not dict:return False
    detail=response.get('Error',{})
    if type(detail) is not dict:return False
    code=detail.get('Code')
    if code == 'ConditionalCheckFailedException':return True
    reasons=response.get('CancellationReasons')
    return (code == 'TransactionCanceledException' and type(reasons) is list and bool(reasons)
            and all(type(r) is dict and r.get('Code') in ('None','ConditionalCheckFailed') for r in reasons)
            and any(r['Code'] == 'ConditionalCheckFailed' for r in reasons))


def _challenge(value):
    require(type(value) is dict and set(value) == {'profile','nonce','scope','facts','identity','registry_sequence',
                                                  'created_at','expires_at'} and value['profile'] == PROFILE,
            'action-challenge')
    hex_string(value['nonce'],64);hex_string(value['scope'],64)
    timestamp(value['created_at']);timestamp(value['expires_at'])
    require(type(value['identity']) is bool and type(value['registry_sequence']) is int
            and 0 <= value['registry_sequence'] <= MAX_REVISION
            and value['created_at'] < value['expires_at'] <= value['created_at']+60
            and type(value['facts']) is list and 1 <= len(value['facts']) <= 2
            and all(type(f) is str and f in {'account-controlled','followers-at-least-10000'} for f in value['facts'])
            and value['facts'] == sorted(set(value['facts'])),'action-challenge')
    return canonical(value)


class DynamoPublicStore:
    production_antirollback=False

    def __init__(self,client,table,namespace):
        require(type(table) is str and re.fullmatch(r'[A-Za-z0-9_.-]{3,255}',table),'registry-table')
        hex_string(namespace,64);require(any(bytes.fromhex(namespace)),'registry-namespace')
        self._client=client;self.table=table;self.namespace=namespace

    def key(self,suffix):return {'id':{'S':self.namespace+':'+suffix}}

    def _get(self,suffix):
        try:
            response=self._client.get_item(TableName=self.table,Key=self.key(suffix),ConsistentRead=True)
            require(type(response) is dict,'registry-response')
            return response.get('Item')
        except Rejected:raise
        except Exception:raise Rejected('registry-unavailable') from None

    def _public(self,item):
        require(type(item) is dict and set(item) == {'id','revision','definition_hash','sequence','view'}
                and item['id'] == self.key('public')['id']
                and item['definition_hash'] == {'S':self.namespace}
                and type(item['view']) is dict and set(item['view']) == {'B'},'registry-public-projection')
        revision=_number(item['revision']);sequence=_number(item['sequence'])
        view=strict_json(item['view']['B'])
        require(set(view) == {'definition_hash','sequence','public'} and view['definition_hash'] == self.namespace
                and type(view['sequence']) is int and view['sequence'] == sequence
                and type(view['public']) is dict and definition_hash(view['public']) == self.namespace,
                'registry-public-projection')
        return revision,view

    def public_view(self):return self._public(self._get('public'))[1]

    def _current_condition(self,sequence):
        return {'ConditionCheck':{'TableName':self.table,'Key':self.key('public'),
            'ConditionExpression':'#sequence = :sequence AND #definition = :definition',
            'ExpressionAttributeNames':{'#sequence':'sequence','#definition':'definition_hash'},
            'ExpressionAttributeValues':{':sequence':{'N':str(sequence)},':definition':{'S':self.namespace}}}}

    def _write(self,items,conflict='registry-conflict'):
        try:self._client.transact_write_items(TransactItems=items)
        except Exception as error:
            raise Rejected(conflict if _conflict(error) else 'registry-unavailable') from None


class DynamoIssuerStore(DynamoPublicStore):
    """Private ciphertext and public registry publish in one transaction."""
    def read(self):
        try:
            response=self._client.transact_get_items(TransactItems=[
                {'Get':{'TableName':self.table,'Key':self.key('issuer')}},
                {'Get':{'TableName':self.table,'Key':self.key('public')}}])
            rows=response['Responses'];require(type(rows) is list and len(rows) == 2,'registry-response')
            require(all(type(row) is dict and set(row) <= {'Item'} for row in rows),'registry-response')
            state,public=(row.get('Item') for row in rows)
            if state is None and public is None:return None,None
            require(type(state) is dict and set(state) == {'id','revision','envelope'}
                    and state['id'] == self.key('issuer')['id']
                    and type(state['envelope']) is dict and set(state['envelope']) == {'B'},'registry-item')
            revision=_number(state['revision']);public_revision,_=self._public(public)
            envelope=state['envelope']['B']
            require(revision == public_revision and type(envelope) is bytes and 28 < len(envelope) <= LIMIT+28,
                    'registry-item')
            return revision,envelope
        except Rejected:raise
        except Exception:raise Rejected('registry-unavailable') from None

    def compare_exchange(self,expected,envelope,public):
        require(expected is None or type(expected) is int and 0 <= expected < MAX_REVISION,'registry-revision')
        require(type(envelope) is bytes and 28 < len(envelope) <= LIMIT+28,'registry-envelope')
        require(type(public) is dict,'registry-public-projection')
        revision=0 if expected is None else expected+1
        public_item={'id':self.key('public')['id'],'revision':{'N':str(revision)},
            'definition_hash':{'S':self.namespace},'sequence':{'N':str(public.get('sequence'))},'view':{'B':canonical(public)}}
        self._public(public_item)
        state_item={'id':self.key('issuer')['id'],'revision':{'N':str(revision)},'envelope':{'B':envelope}}
        items=[]
        for item in (state_item,public_item):
            put={'TableName':self.table,'Item':item,'ExpressionAttributeNames':{'#id':'id'}}
            if expected is None:put['ConditionExpression']='attribute_not_exists(#id)'
            else:
                put.update({'ConditionExpression':'attribute_exists(#id) AND #revision = :expected',
                            'ExpressionAttributeValues':{':expected':{'N':str(expected)}}})
                put['ExpressionAttributeNames']['#revision']='revision'
            items.append({'Put':put})
        self._write(items)
        return revision


class DynamoActionStore(DynamoPublicStore):
    """Public material and action metadata only; no issuer ciphertext methods."""
    def register_action(self,challenge):
        body=_challenge(challenge)
        item={**self.key('action:'+challenge['nonce']),'body':{'B':body},'used':{'N':'0'}}
        self._write([self._current_condition(challenge['registry_sequence']),{'Put':{'TableName':self.table,
            'Item':item,'ConditionExpression':'attribute_not_exists(#id)','ExpressionAttributeNames':{'#id':'id'}}}],
            'action-not-outstanding')

    def action_record(self,nonce):
        hex_string(nonce,64);item=self._get('action:'+nonce)
        if item is None:return None
        require(type(item) is dict and set(item) == {'id','body','used'}
                and item['id'] == self.key('action:'+nonce)['id']
                and type(item['body']) is dict and set(item['body']) == {'B'},'action-record')
        body=item['body']['B'];challenge=strict_json(body)
        require(_challenge(challenge) == body and challenge['nonce'] == nonce,'action-record')
        used=_number(item['used']);require(used in (0,1),'action-record')
        return body,bool(used)

    def consume_action(self,challenge):
        body=_challenge(challenge)
        self._write([self._current_condition(challenge['registry_sequence']),{'Update':{
            'TableName':self.table,'Key':self.key('action:'+challenge['nonce']),
            'UpdateExpression':'SET #used = :one',
            'ConditionExpression':'#body = :body AND #used = :zero',
            'ExpressionAttributeNames':{'#body':'body','#used':'used'},
            'ExpressionAttributeValues':{':body':{'B':body},':zero':{'N':'0'},':one':{'N':'1'}}}}],
            'action-not-outstanding')


class DynamoBudget(DynamoPublicStore):
    """Burn a conservative paid-request allowance BEFORE any provider dialing.

    initialize() is a provisioner operation, never automatic startup recovery.
    Runtime IAM must not allow Put/Delete of the budget item. No refunds/retries.
    """
    def initialize(self):
        try:
            self._client.put_item(TableName=self.table,Item={**self.key('budget'),
                'cap':{'N':str(CAP_MICRO_USD)},'spent':{'N':'0'}},
                ConditionExpression='attribute_not_exists(#id)',ExpressionAttributeNames={'#id':'id'})
        except Exception as error:
            raise Rejected('budget-already-initialized' if _conflict(error) else 'registry-unavailable') from None

    def reserve(self,request_id,operation):
        hex_string(request_id,32);require(type(operation) is str and operation in OPERATIONS,'budget-operation')
        self._write([{'Put':{'TableName':self.table,'Item':{**self.key('charge:'+request_id),
            'operation':{'S':operation},'micro_usd':{'N':str(PER_REQUEST_MICRO_USD)}},
            'ConditionExpression':'attribute_not_exists(#id)','ExpressionAttributeNames':{'#id':'id'}}},
            {'Update':{'TableName':self.table,'Key':self.key('budget'),
                'UpdateExpression':'SET #spent = #spent + :cost',
                'ConditionExpression':'attribute_exists(#id) AND #cap = :cap AND #spent <= :max',
                'ExpressionAttributeNames':{'#id':'id','#cap':'cap','#spent':'spent'},
                'ExpressionAttributeValues':{':cost':{'N':str(PER_REQUEST_MICRO_USD)},
                    ':cap':{'N':str(CAP_MICRO_USD)},':max':{'N':str(CAP_MICRO_USD-PER_REQUEST_MICRO_USD)}}}}],
            'api-spending-limit')

    def public_summary(self):
        item=self._get('budget')
        require(type(item) is dict and set(item) == {'id','cap','spent'}
                and item['id'] == self.key('budget')['id'] and _number(item['cap']) == CAP_MICRO_USD,'budget-item')
        spent=_number(item['spent'])
        require(spent <= CAP_MICRO_USD and spent % PER_REQUEST_MICRO_USD == 0,'budget-item')
        return {'cap_usd':'3.00','reserved_request_count':spent//PER_REQUEST_MICRO_USD,
                'conservative_reserved_usd':f'{spent/1000000:.2f}',
                'billing_observed':False,'other_applications_excluded':True}


def role_policies(table_arn,namespace):
    """Concrete review fragments. Parent gets NONE of these managed permissions."""
    require(type(table_arn) is str and re.fullmatch(
        r'arn:aws:dynamodb:[a-z]{2}-[a-z]+-[1-9]:[0-9]{12}:table/[A-Za-z0-9_.-]{3,255}',table_arn),'registry-table-arn')
    hex_string(namespace,64);require(any(bytes.fromhex(namespace)),'registry-namespace')
    def statement(sid,actions,keys,like=False):
        return {'Sid':sid,'Effect':'Allow','Action':['dynamodb:'+a for a in actions],'Resource':table_arn,
                'Condition':{'ForAllValues:StringLike' if like else 'ForAllValues:StringEquals':
                             {'dynamodb:LeadingKeys':[namespace+':'+k for k in keys]},
                             'Null':{'dynamodb:LeadingKeys':'false'}}}
    def policy(*statements):return {'Version':'2012-10-17','Statement':list(statements)}
    def transactional(s,operation):
        s['Condition']['ForAnyValue:StringEquals']={'dynamodb:EnclosingOperation':[operation]}
        return s
    return {'issuer':policy(statement('ReadPublicRegistry',['GetItem'],['public']),
                transactional(statement('ReadPrivateSnapshot',['GetItem'],['issuer']),'TransactGetItems'),
                transactional(statement('PublishPrivateAndPublic',['PutItem'],['issuer','public']),'TransactWriteItems')),
            'verifier':policy(statement('CurrentPublicRegistry',['GetItem','ConditionCheckItem'],['public']),
                statement('ReadActionMetadata',['GetItem'],['action:*'],True),
                transactional(statement('SingleUseActionMetadata',['PutItem','UpdateItem'],['action:*'],True),'TransactWriteItems')),
            'budget':policy(statement('ReadBudgetCounter',['GetItem'],['budget']),
                transactional(statement('ExistingBudgetCounter',['UpdateItem'],['budget']),'TransactWriteItems'),
                transactional(statement('BurnUniqueCharge',['PutItem'],['charge:*'],True),'TransactWriteItems')),
            'budget_initializer':policy(statement('InitializeBudgetOnce',['PutItem'],['budget'])),
            'public_reader':policy(statement('PublicRegistryOnly',['GetItem'],['public']))}


def authority_identity(config):
    """Bind actual immutable table/region/roles and reviewable grants into quotes.

    This validates a descriptor, not existing AWS permissions or table topology.
    The measured supervisor must construct its clients from this SAME config.
    """
    require(type(config) is dict and set(config) == {'region','table_arn','namespace','roles'},'authority-config')
    require(type(config['region']) is str and re.fullmatch(r'[a-z]{2}-[a-z]+-[1-9]',config['region']),
            'authority-config')
    policies=role_policies(config['table_arn'],config['namespace'])
    arn=config['table_arn'].split(':');account=arn[4]
    require(arn[3] == config['region'] and type(config['roles']) is dict
            and set(config['roles']) == {'issuer','verifier','budget','public_reader'},'authority-config')
    for role in config['roles'].values():
        require(type(role) is str and re.fullmatch('arn:aws:iam::'+account+r':role/[A-Za-z0-9_+=,.@/-]+',role),
                'authority-config')
    require(len(set(config['roles'].values())) == 4,'authority-roles-must-differ')
    descriptor={'profile':'nockapp-zkid-composite-managed-authority-v1','config':config,
                'consistency':'single-region-strong-transactional',
                'dynamodb_endpoint':'https://dynamodb.'+config['region']+'.amazonaws.com/',
                'kms_endpoint':'https://kms.'+config['region']+'.amazonaws.com/',
                'schema':'issuer/public/action/budget/charge-v1','policies_sha256':digest(policies),
                'budget_micro_usd':CAP_MICRO_USD,'per_request_micro_usd':PER_REQUEST_MICRO_USD}
    return digest(descriptor)
