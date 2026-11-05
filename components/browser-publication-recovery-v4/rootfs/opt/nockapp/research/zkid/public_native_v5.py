"""Strict v5 public-app native operations; caller never supplies keys or trust."""
from policy import require


class PublicApplicationV5:
    def __init__(self,desktop,*,count_desktop=None,count_provider=None):
        require((count_desktop is None)==(count_provider is None),'v5-count-config')
        if count_desktop is not None:require(count_desktop in desktop.author.legacy_sources,'v5-count-config')
        self.desktop=desktop;self.count_desktop=count_desktop;self.count_provider=count_provider

    def dispatch(self,operation,body):
        require(type(operation) is str and type(body) is dict,'v5-native-schema');d=self.desktop
        if operation in ('public-archive-capabilities','public-archive-export-object','public-archive-import-object','public-archive-cache-status'):
            from public_archive_native_v5 import dispatch
            return dispatch(d,operation,body)
        if operation=='public-capabilities':
            require(not body,'v5-native-schema')
            return {'configured':True,'protocol':5,'scope':d.scope,'follower_proof_configured':self.count_provider is not None}
        if operation=='public-initialize-identity':
            require(set(body)=={'approve_private_key_setup'},'v5-native-schema')
            return d.initialize_identity(body['approve_private_key_setup'])
        if operation=='public-prepare':
            require(set(body)=={'post','selection','thread','references','approve_publication'},'v5-native-schema')
            return d.prepare(body['post'],body['selection'],body['approve_publication'],thread=body['thread'],references=body['references'])
        if operation in ('public-finish','public-publish'):
            fields={'post_id','approve_publication'}
            extra={'approve_optional_badge_failure'}
            require((set(body)==fields or operation=='public-publish' and set(body)==fields|extra
                     and body['approve_optional_badge_failure'] is True)
                    and body['approve_publication'] is True,'consent-required')
            if operation=='public-finish':return d.finish(body['post_id'])
            if body.get('approve_optional_badge_failure') is True:
                return d.publish(body['post_id'],True,approve_optional_badge_failure=True)
            return d.publish(body['post_id'],True)
        if operation=='public-check':
            require(set(body)=={'post_id'},'v5-native-schema');return d.check(body['post_id'])
        if operation=='public-address-request':
            require(set(body)=={'post_id','address','approve_address_disclosure'},'v5-native-schema')
            return d.request_address(body['post_id'],body['address'],body['approve_address_disclosure'])
        if operation=='public-address-result':
            require(set(body)=={'post_id','request_sha256','signature'},'v5-native-schema')
            return d.accept_address(body['post_id'],body['request_sha256'],body['signature'])
        if operation=='public-reset-unfinished-address':
            require(set(body)=={'post_id','request_sha256','approve_fresh_request'},'v5-native-schema')
            return d.reset_unfinished_address(body['post_id'],body['request_sha256'],body['approve_fresh_request'])
        if operation=='public-attach-followers':
            require(set(body)=={'post_id','approve_follower_disclosure'} and body['approve_follower_disclosure'] is True,'consent-required')
            require(self.count_provider is not None,'v5-count-unavailable')
            view,witness=self.count_provider.refresh()
            return d.attach_count(body['post_id'],self.count_desktop,view,witness)
        if operation=='public-attach-history':
            require(set(body)=={'post_id','records','approve_linking'},'v5-native-schema')
            return d.attach_history(body['post_id'],body['records'],d.reader.resolve_original,body['approve_linking'])
        if operation=='public-export-submission':
            require(set(body)=={'post_id','approve_public_export'},'v5-native-schema')
            return d.export_submission(body['post_id'],body['approve_public_export'])
        if operation=='public-outbox':
            require(set(body)=={'after','limit'} and type(body['limit']) is int and 1<=body['limit']<=4,'v5-native-page')
            return d.outbox(body['after'],body['limit'])
        if operation=='public-numbers':
            require(set(body)=={'numbers'} and type(body['numbers']) is list and len(body['numbers'])<=4,'v5-native-page')
            return d.reader.read_numbers(body['numbers'],int(d.clock()))
        require(False,'v5-native-operation')
