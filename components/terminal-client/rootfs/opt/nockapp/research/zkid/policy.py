"""Strict public-challenge policy for the separate scraper-trusting ZKID path.

No credentials, X sessions, arbitrary URLs, or caller-supplied eligibility bits.
This is application logic; it does not turn scraped data into direct X evidence.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import http.client
import json
import re
import secrets
import socket
import ssl
import threading
import time
from urllib.parse import urlencode

PROFILE = 'nockapp-zkid-blind-research-v1'
SOURCE = 'twitterapi.io'
HOST = 'api.twitterapi.io'
MAX_RESPONSE = 131072
SESSION_SECONDS = 600
DISCOVERY_INTERVAL = 30
DISCOVERY_ATTEMPTS = 20
POLICY = {
    'profile': PROFILE, 'source': SOURCE, 'host': HOST,
    'account_control': 'fresh-exact-public-post-bound-to-blind-request',
    'followers': 'same-stable-account-id;at-least-10000',
    'session_seconds': SESSION_SECONDS, 'cohort_seconds': 3600,
    'credential_seconds': 86400, 'max_response_bytes': MAX_RESPONSE,
    'source_honesty_required': True,
    'nonce_sources': 'desktop-and-issuer-independent-random-256-bit',
    'public_challenge_prefix': 'testing:',
}


class Rejected(Exception):
    """Fixed safe codes only; raw upstream errors/responses must not escape."""


def require(condition, code):
    if not condition:
        raise Rejected(code) from None


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


POLICY_HASH = digest(POLICY)


def strict_json(data, *, max_bytes=MAX_RESPONSE):
    require(type(max_bytes) is int and 0 < max_bytes <= 1048576
            and type(data) is bytes and 0 < len(data) <= max_bytes, 'source-response-size')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'source-duplicate-key')
            result[key] = value
        return result
    try:
        value = json.loads(data.decode('utf-8'), object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(Rejected('source-json')))
        pending = [(value, 0)]
        count = 0
        while pending:
            item, depth = pending.pop()
            count += 1
            require(depth <= 24 and count <= 8192, 'source-json-limits')
            if type(item) is dict:
                pending.extend((v, depth + 1) for v in item.values())
            elif type(item) is list:
                pending.extend((v, depth + 1) for v in item)
        require(type(value) is dict, 'source-schema')
        return value
    except Rejected:
        raise
    except Exception:
        raise Rejected('source-json') from None


def identifier(value):
    require(type(value) is str and re.fullmatch(r'[1-9][0-9]{0,19}', value) is not None
            and int(value) < 2**64, 'account-or-post-id')
    return value


def hex_string(value, length):
    require(type(value) is str and re.fullmatch('[0-9a-f]{%d}' % length, value) is not None,
            'request-encoding')
    return value


def timestamp(value):
    require(type(value) is int and 0 < value < 2**53, 'timestamp')
    return value


@dataclass(frozen=True)
class Session:
    """Issued/retained by trusted controller, never reconstructed from a claim."""
    nonce: str
    desktop_nonce: str
    commitment: str
    account_id: str
    username: str
    issuer_key: str
    created_at: int
    request_scheme: str = 'blind-bbs-sha256-research'

    def __post_init__(self):
        hex_string(self.nonce, 64)
        hex_string(self.desktop_nonce, 64)
        require(self.request_scheme in ('blind-bbs-sha256-research','anoncreds-cl-0.2.3',
                                       'credx-bbs-domain-0.2.1'), 'request-scheme')
        # BBS baseline uses its complete fixed-size commitment. The revocable
        # AnonCreds candidate binds the SHA-256 of its complete blinded request.
        hex_string(self.commitment, 288 if self.request_scheme == 'blind-bbs-sha256-research' else 64)
        identifier(self.account_id)
        require(type(self.username) is str and re.fullmatch(r'[A-Za-z0-9_]{1,15}', self.username),
                'account-handle')
        hex_string(self.issuer_key, 192 if self.request_scheme == 'blind-bbs-sha256-research' else 64)
        timestamp(self.created_at)

    @classmethod
    def create(cls, desktop_nonce, commitment, account_id, username, issuer_key, now,
               *, request_scheme='blind-bbs-sha256-research'):
        return cls(secrets.token_hex(32), desktop_nonce, commitment, account_id, username, issuer_key,
                   timestamp(now), request_scheme)

    @property
    def binding(self):
        return digest({'profile': PROFILE, 'policy': POLICY_HASH, **self.__dict__})

    @property
    def post_text(self):
        return POLICY['public_challenge_prefix'] + self.binding

    def check_time(self, now):
        require(self.created_at <= timestamp(now) <= self.created_at + SESSION_SECONDS, 'session-expired')


def user(value, account_id, username):
    require(type(value) is dict and value.get('type') == 'user', 'source-user-schema')
    require(value.get('id') == account_id, 'source-account-mismatch')
    require(type(value.get('userName')) is str and value['userName'].lower() == username.lower(),
            'source-handle-mismatch')
    require(value.get('unavailable', False) is False and value.get('protected', False) is False,
            'source-account-unavailable')
    count = value.get('followers')
    require(type(count) is int and 0 <= count < 2**53, 'source-follower-count')
    return count


def profile_user(value, account_id, username):
    """Decode only the fixed user/info endpoint's profile object.

    Some provider profile shapes omit the redundant user discriminator. Its
    absence does not replace any account/handle/count/status check. A supplied
    discriminator must still be exactly user. Tweet authors remain strict.
    """
    require(type(value) is dict, 'source-profile-object')
    require('type' not in value or value['type'] == 'user', 'source-profile-type')
    return user({**value, 'type': 'user'}, account_id, username)


def challenge_post(session, tweet_id, tweet, now):
    """Validate a candidate; this alone neither issues nor evaluates metrics."""
    session.check_time(now)
    identifier(tweet_id)
    require(type(tweet) is dict and tweet.get('type') == 'tweet' and tweet.get('id') == tweet_id,
            'source-post-mismatch')
    require(tweet.get('text') == session.post_text, 'source-challenge-mismatch')
    require(tweet.get('retweeted_tweet') is None and tweet.get('quoted_tweet') is None
            and tweet.get('isReply', False) is False, 'source-original-post-required')
    user(tweet.get('author'), session.account_id, session.username)
    try:
        created = tweet['createdAt']
        require(type(created) is str, 'source-post-time')
        moment = datetime.strptime(created, '%a %b %d %H:%M:%S %z %Y')
        require(moment.utcoffset().total_seconds() == 0, 'source-post-time')
        post_time = int(moment.timestamp())
    except Rejected:
        raise
    except Exception:
        raise Rejected('source-post-time') from None
    require(session.created_at <= post_time <= now + 5, 'source-stale-post')


def discovery_candidate(session, data, now):
    """One authenticated timeline page supplies ONLY a candidate post ID.

    Ignore pinned posts and never follow provider cursors. A candidate is checked
    again by the existing fixed tweet/profile path before credential issuance.
    No timeline body or unrelated post leaves this parser.
    """
    session.check_time(now)
    value = strict_json(data)
    require(value.get('status') == 'success' and type(value.get('code', 0)) is int
            and value.get('code', 0) == 0, 'source-error')
    payload = value.get('data')
    require(type(payload) is dict and type(payload.get('tweets')) is list
            and len(payload['tweets']) <= 20, 'source-discovery-schema')
    require(type(value.get('has_next_page')) is bool and type(value.get('next_cursor')) is str
            and len(value['next_cursor']) <= 4096, 'source-discovery-schema')
    seen = set(); found = []
    for tweet in payload['tweets']:
        require(type(tweet) is dict and tweet.get('type') == 'tweet'
                and type(tweet.get('text')) is str, 'source-discovery-schema')
        ident = identifier(tweet.get('id'))
        require(ident not in seen, 'source-discovery-schema'); seen.add(ident)
        if tweet['text'] == session.post_text:
            challenge_post(session, ident, tweet, now)
            found.append(ident)
    return min(found, key=int) if found else None


def evaluate(session, tweet_id, tweet_data, user_data, now):
    """Input bytes MUST come from authenticated provider TLS inside the enclave.

    Pure function is separately adversarially tested. Calling it on supplied
    bytes does not establish source authenticity, attestation, or authorization.
    """
    session.check_time(now)
    identifier(tweet_id)
    tweets, info = strict_json(tweet_data), strict_json(user_data)
    require(tweets.get('status') == 'success' and tweets.get('code', 0) == 0
            and type(tweets.get('code', 0)) is int and info.get('status') == 'success', 'source-error')
    items = tweets.get('tweets')
    require(type(items) is list and len(items) == 1 and type(items[0]) is dict, 'source-post-count')
    challenge_post(session, tweet_id, items[0], now)
    count = profile_user(info.get('data'), session.account_id, session.username)
    cohort = now // 3600 * 3600
    # Coarse observation windows avoid assigning a unique timestamp to each user.
    return [PROFILE, SOURCE, POLICY_HASH, str(cohort), str(cohort + 86400), '1',
            '1' if count >= 10000 else '0']


class ProviderClient:
    """Fixed provider API; authenticate TLS HERE, including over a vsock relay.

    api_key is provided by the enclave's secret provisioner, never config/argv.
    dial, when supplied, opens ONLY the measured fixed vsock relay endpoint.
    This code never calls the provider unless explicitly invoked by its owner.
    """
    def __init__(self, api_key, context, dial=None, *, budget=None):
        require(type(api_key) is str and re.fullmatch(r'[A-Za-z0-9_-]{16,256}', api_key), 'provider-key-format')
        require(isinstance(context, ssl.SSLContext) and context.verify_mode == ssl.CERT_REQUIRED
                and context.check_hostname and context.minimum_version >= ssl.TLSVersion.TLSv1_2,
                'source-tls-required')
        self._key, self._context = api_key, context
        self._dial = dial or (lambda: socket.create_connection((HOST, 443), timeout=10))
        self._budget=budget
        self.budget_enforced=budget is not None

    def _get(self, path):
        if re.fullmatch(r'/twitter/tweets\?tweet_ids=[1-9][0-9]{0,19}',path):operation='one-public-post'
        elif re.fullmatch(r'/twitter/user/info\?userName=[A-Za-z0-9_]{1,15}',path):operation='one-user-profile'
        elif re.fullmatch(r'/twitter/user/last_tweets\?userId=[1-9][0-9]{0,19}',path):operation='one-timeline-page'
        else:raise Rejected('provider-path-forbidden')
        if self._budget is not None:self._budget.reserve(secrets.token_hex(16),operation)
        raw = secure = connection = None
        timer = None
        deadline = time.monotonic() + 12
        try:
            raw = self._dial()
            raw.settimeout(10)
            # A per-read socket timeout alone does not bound slow-drip peers.
            def expire():
                stream = secure or raw
                try:
                    stream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            timer = threading.Timer(max(0.001, deadline - time.monotonic()), expire)
            timer.daemon = True
            timer.start()
            secure = self._context.wrap_socket(raw, server_hostname=HOST)
            connection = http.client.HTTPConnection(HOST, timeout=10)
            connection.sock = secure
            connection.request('GET', path, headers={'X-API-Key': self._key,
                'Accept': 'application/json', 'Accept-Encoding': 'identity', 'Connection': 'close'})
            response = connection.getresponse()
            if response.status == 429:
                raise Rejected('provider-rate-limit')
            require(response.status == 200, 'provider-http-error')
            headers = response.getheaders()
            for name in ('Content-Length', 'Transfer-Encoding', 'Content-Type', 'Content-Encoding'):
                require(sum(k.lower() == name.lower() for k, _ in headers) <= 1, 'source-http-ambiguous')
            require(not (response.getheader('Content-Length') and response.getheader('Transfer-Encoding')),
                    'source-http-ambiguous')
            require(response.getheader('Content-Encoding', 'identity').lower() == 'identity', 'source-encoding')
            require(response.getheader('Transfer-Encoding', '').lower() in ('', 'chunked'), 'source-encoding')
            require(response.getheader('Content-Type', '').split(';')[0].lower() == 'application/json', 'source-content-type')
            length = response.getheader('Content-Length')
            if length is not None:
                require(re.fullmatch(r'[0-9]+', length) and int(length) <= MAX_RESPONSE, 'source-response-size')
            data = response.read(MAX_RESPONSE + 1)
            require(len(data) <= MAX_RESPONSE, 'source-response-size')
            if length is not None:
                require(len(data) == int(length), 'source-truncated')
            return data
        except Rejected:
            raise
        except Exception:
            raise Rejected('provider-unavailable') from None
        finally:
            if timer:
                timer.cancel()
            if connection:
                connection.close()
            elif secure:
                secure.close()
            elif raw:
                raw.close()

    def resolve(self, username):
        require(type(username) is str and re.fullmatch(r'[A-Za-z0-9_]{1,15}',username),'account-handle')
        value=strict_json(self._get('/twitter/user/info?'+urlencode({'userName':username})))
        require(value.get('status')=='success' and value.get('code',0)==0,'source-user-status')
        data=value.get('data');require(type(data) is dict,'source-profile-object')
        account_id=identifier(data.get('id'));profile_user(data,account_id,username)
        return account_id

    def check(self, session, tweet_id, now):
        session.check_time(now)
        identifier(tweet_id)
        tweets = self._get('/twitter/tweets?' + urlencode({'tweet_ids': tweet_id}))
        info = self._get('/twitter/user/info?' + urlencode({'userName': session.username}))
        return evaluate(session, tweet_id, tweets, info, now)

    def discover(self, session, clock):
        # clock belongs to the measured controller, never the RPC caller.
        # A user may publish DURING the request; validate at response time.
        require(callable(clock),'discovery-clock')
        session.check_time(clock())
        data=self._get('/twitter/user/last_tweets?'+urlencode({'userId':session.account_id}))
        return discovery_candidate(session,data,clock())
