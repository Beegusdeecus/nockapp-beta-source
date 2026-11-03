"""Versioned raw-count policy. Old fixed bits are never raw follower counts."""
from dataclasses import dataclass
import secrets

from policy import (POLICY,Session,digest,evaluate,hex_string,identifier,profile_user,
    require,strict_json,timestamp)

PROFILE='nockapp-zkid-count-source-v2'
MAX_COUNT=2**53-1
COUNT_POLICY={**POLICY,'profile':PROFILE,'followers':'same-stable-account-id;private-authenticated-integer-count',
    'credential_schema':'nockapp-zkid-count-application-v2','count_min':0,'count_max':MAX_COUNT,
    'threshold_predicate':'strict-greater-than;inclusive-lower=threshold+1;linked-signed-claim',
    'exact_count_disclosure':'explicit-per-post-only'}
POLICY_HASH=digest(COUNT_POLICY)
SCHEME='credx-bbs-count-0.2.1-v2'


@dataclass(frozen=True)
class CountSession(Session):
    request_scheme: str=SCHEME

    def __post_init__(self):
        hex_string(self.nonce,64);hex_string(self.desktop_nonce,64);hex_string(self.commitment,64)
        hex_string(self.issuer_key,64);identifier(self.account_id);timestamp(self.created_at)
        require(self.request_scheme==SCHEME,'request-scheme')
        import re
        require(type(self.username) is str and re.fullmatch(r'[A-Za-z0-9_]{1,15}',self.username),'account-handle')

    @classmethod
    def create(cls,desktop_nonce,commitment,account_id,username,issuer_key,now,*,request_scheme=SCHEME):
        return cls(secrets.token_hex(32),desktop_nonce,commitment,account_id,username,issuer_key,timestamp(now),request_scheme)

    @property
    def binding(self):return digest({'profile':PROFILE,'policy':POLICY_HASH,**self.__dict__})


def evaluate_count(session,tweet_id,tweet_data,user_data,now):
    require(type(session) is CountSession and session.request_scheme==SCHEME,'count-session-version')
    # Reuse every authenticated source/account/post/time check. Recover the raw
    # private count from the SAME checked response, never the derived v1 bit.
    values=evaluate(session,tweet_id,tweet_data,user_data,now)
    info=strict_json(user_data)
    count=profile_user(info['data'],session.account_id,session.username)
    require(type(count) is int and 0<=count<=MAX_COUNT,'source-follower-count')
    return [PROFILE,values[1],POLICY_HASH,*values[3:6],str(count)]


def threshold(value):
    require(type(value) is int and 0<=value<=MAX_COUNT,'follower-threshold')
    return value
