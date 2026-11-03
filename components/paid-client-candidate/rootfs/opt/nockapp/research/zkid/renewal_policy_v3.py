"""Six calendar months, private credential dates, fresh authenticated source check.

This is a versioned policy, never a reinterpretation of old24-hour credentials.
Caller must obtain source bytes through the approved enclave TLS provider.
"""
from dataclasses import dataclass
from datetime import datetime,timezone
import calendar
import secrets
from policy import Session,ProviderClient,canonical,digest,evaluate,hex_string,identifier,profile_user,require,strict_json,timestamp

PROFILE='nockapp-renewal-count-v3'
MAX_COUNT=2**53-1
MAX_TIME=2**32-1
POLICY={'profile':'nockapp-renewal-policy-v3','source':'twitterapi.io','credential_schema':PROFILE,
    'count_max':MAX_COUNT,'renewal':'six-calendar-months-UTC-clamp-month-end;fresh-source-challenge',
    'public_disclosures':['source','policy','controlled'],
    'dates':'hidden-issued-at-and-renew-by;linked-ranges-cover-publication-window',
    'threshold':'signed-followers-strictly-greater-than-selected',
    'revocation':'canonical-issuer-accumulator-at-indexing','display':'persistent-qualified-when-indexed','time_max':MAX_TIME}
POLICY_HASH=digest(POLICY)
SCHEME='credx-bbs-renewal-v3'

def six_months(issued_at):
    require(type(issued_at) is int and 0<issued_at<=MAX_TIME,'renewal-time')
    d=datetime.fromtimestamp(issued_at,timezone.utc);offset=d.year*12+d.month-1+6;year,month=divmod(offset,12);month+=1
    end=d.replace(year=year,month=month,day=min(d.day,calendar.monthrange(year,month)[1]))
    value=int(end.timestamp());require(value<=MAX_TIME,'renewal-time');return value

@dataclass(frozen=True)
class RenewalSession(Session):
    request_scheme:str=SCHEME

    def __post_init__(self):
        for value in (self.nonce,self.desktop_nonce,self.commitment,self.issuer_key):hex_string(value,64)
        identifier(self.account_id);timestamp(self.created_at)
        import re
        require(self.request_scheme==SCHEME and type(self.username) is str
            and re.fullmatch(r'[A-Za-z0-9_]{1,15}',self.username),'renewal-session')

    @classmethod
    def create(cls,desktop_nonce,commitment,account_id,username,issuer_key,now,*,request_scheme=SCHEME):
        return cls(secrets.token_hex(32),desktop_nonce,commitment,account_id,username,issuer_key,now,request_scheme)

    @property
    def binding(self):return digest({'profile':PROFILE,'policy':POLICY_HASH,**self.__dict__})

def evaluate_renewal(session,tweet_id,tweet_data,user_data,now):
    require(type(session) is RenewalSession,'renewal-session')
    evaluate(session,tweet_id,tweet_data,user_data,now) # All prior exact account/post/time/source checks.
    data=strict_json(user_data);count=profile_user(data['data'],session.account_id,session.username)
    require(type(count) is int and 0<=count<=MAX_COUNT,'source-follower-count')
    return {'source':'twitterapi.io','policy':POLICY_HASH,'issued_at':now,'renew_by':six_months(now),
        'controlled':1,'followers':count,'binding':session.binding}

class RenewalProvider(ProviderClient):
    def check(self,session,tweet_id,now):
        require(type(session) is RenewalSession,'renewal-session');identifier(tweet_id);session.check_time(now)
        from urllib.parse import urlencode
        tweets=self._get('/twitter/tweets?'+urlencode({'tweet_ids':tweet_id}))
        info=self._get('/twitter/user/info?'+urlencode({'userName':session.username}))
        return evaluate_renewal(session,tweet_id,tweets,info,now)
