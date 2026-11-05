"""Verifier-role managed action receipt, never issuer/private-state access.

Same managed transaction as nonce consumption pins proof digest + observation
window. No proof, credential or public ID enters the managed metadata item.
No cloud resource/client/credential is created or discovered here.
"""
from domain_authority import DynamoActionStore,_challenge,_number
from policy import canonical,hex_string,require,strict_json,timestamp

RECEIPT='nockapp-zkid-post-acceptance-receipt-v1'


def validate_receipt(value,challenge):
    require(type(value) is dict and set(value)=={'profile','proof_sha256','accepted_at','observed_at','expires_at'}
            and value['profile']==RECEIPT,'post-receipt')
    hex_string(value['proof_sha256'],64)
    for key in ('accepted_at','observed_at','expires_at'):timestamp(value[key])
    require(challenge['identity'] is False and challenge['created_at']<=value['accepted_at']<challenge['expires_at']
            and value['observed_at']%3600==0 and value['expires_at']-value['observed_at']==86400
            and value['observed_at']<=value['accepted_at']<value['expires_at'],'post-receipt')
    return value


class DynamoPostActions(DynamoActionStore):
    """Receipt publication + nonce burn + current registry condition are ATOMIC.

    Existing verifier-role action:* grants apply; issuer/budget/public-reader
    roles cannot publish action receipts. Effective IAM remains a deployment gate.
    """
    def _record(self,nonce):
        hex_string(nonce,64);item=self._get('action:'+nonce)
        if item is None:return None
        require(type(item) is dict and set(item) in ({'id','body','used'},{'id','body','used','receipt'})
                and item['id']==self.key('action:'+nonce)['id'] and type(item['body']) is dict
                and set(item['body'])=={'B'},'action-record')
        body=item['body']['B'];challenge=strict_json(body)
        require(_challenge(challenge)==body and challenge['nonce']==nonce,'action-record')
        used=_number(item['used']);require(used in (0,1) and ('receipt' in item)==bool(used),'action-record')
        receipt=None
        if used:
            require(type(item['receipt']) is dict and set(item['receipt'])=={'B'},'post-receipt')
            receipt=validate_receipt(strict_json(item['receipt']['B']),challenge)
        return body,bool(used),receipt

    def action_record(self,nonce):
        record=self._record(nonce)
        return record[:2] if record is not None else None

    def acceptance(self,nonce):
        record=self._record(nonce)
        return record[2] if record is not None else None

    def consume_action(self,challenge):
        # Never permit the inherited receipt-less update through this role API.
        require(False,'post-receipt-required')

    def consume_post(self,challenge,receipt):
        body=_challenge(challenge);validate_receipt(receipt,challenge)
        item={**self.key('action:'+challenge['nonce']),'body':{'B':body},'used':{'N':'1'},
              'receipt':{'B':canonical(receipt)}}
        self._write([self._current_condition(challenge['registry_sequence']),{'Put':{
            'TableName':self.table,'Item':item,'ConditionExpression':'#body = :body AND #used = :zero',
            'ExpressionAttributeNames':{'#body':'body','#used':'used'},
            'ExpressionAttributeValues':{':body':{'B':body},':zero':{'N':'0'}}}}],'action-not-outstanding')
