"""Fixed-host AWS JSON over authenticated enclave-owned TLS and byte relays.

Pinned botocore handles signing, model validation, serialization and parsing.
No SDK session, credential chain, proxy, retry, URL or ambient AWS config is used.
"""
import copy
import gzip
import http.client
import json
import logging
import re
import socket
import ssl
import sys
import threading
import time

from policy import Rejected, require, strict_json
from provisioning import validate_value
from setup_aws_sdk import activate, SDK
from workload_sessions import WorkloadCredentials

LIMIT = 1048576
OPERATIONS = {'kms':{'Decrypt','GenerateDataKey'},'dynamodb':{'GetItem','PutItem','TransactWriteItems','TransactGetItems'}}
VERSIONS = {'kms':'2014-11-01','dynamodb':'2012-08-10'}
ERRORS = {'ConditionalCheckFailedException','TransactionCanceledException','TransactionConflictException',
          'ProvisionedThroughputExceededException','ThrottlingException','AccessDeniedException',
          'ExpiredTokenException','InvalidSignatureException','UnrecognizedClientException',
          'ResourceNotFoundException','ValidationException','KMSInvalidStateException','IncorrectKeyException',
          'InvalidCiphertextException','InternalServerError','ServiceUnavailable',
          'RequestLimitExceeded','DependencyTimeoutException','KMSInternalException'}


class _NoSdkLogs:
    # SDK debug output includes session tokens and complete response bodies.
    # A sink object prevents root logging configuration from enabling that path.
    @staticmethod
    def debug(*args,**kwargs):pass
    info=warning=error=exception=critical=log=debug
    @staticmethod
    def isEnabledFor(*args,**kwargs):return False


def _silence_sdk():
    for name,module in list(sys.modules.items()):
        if name == 'botocore' or name.startswith('botocore.'):
            for field,value in list(vars(module).items()):
                if isinstance(value,logging.Logger):setattr(module,field,_NoSdkLogs())


class AwsFailure(Rejected):
    def __init__(self,code,reasons=()):
        self.response = {'Error':{'Code':code if code in ERRORS else 'AwsOperationFailed'}}
        if reasons:
            self.response['CancellationReasons'] = [{'Code':r if r in ('None','ConditionalCheckFailed','TransactionConflict')
                                                    else 'Other'} for r in reasons]
        super().__init__('aws-operation-rejected')


class AwsJsonClient:
    """Internal client. Host/region/context/relay come from measured boot config."""
    def __init__(self,service,region,credentials,context,dial=None):
        require(type(service) is str and service in OPERATIONS
                and type(region) is str and re.fullmatch(r'[a-z]{2}-[a-z]+-[1-9]',region),'aws-endpoint')
        require(isinstance(context,ssl.SSLContext) and context.verify_mode == ssl.CERT_REQUIRED
                and context.check_hostname and context.minimum_version >= ssl.TLSVersion.TLSv1_2,'aws-tls-required')
        self._credential_source = credentials if isinstance(credentials,WorkloadCredentials) else None
        self._credential_data = (None if self._credential_source else
                                 copy.deepcopy(validate_value('managed-writer-credentials',credentials)))
        activate()
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
        from botocore.credentials import Credentials
        from botocore.model import ServiceModel
        from botocore.serialize import create_serializer
        from botocore.parsers import create_parser
        _silence_sdk()
        self._SigV4Auth = SigV4Auth;self._AWSRequest = AWSRequest
        self._Credentials=Credentials
        self._credentials = (None if self._credential_source else Credentials(self._credential_data['access_key_id'],
            self._credential_data['secret_access_key'],self._credential_data['session_token']))
        self.service = service;self.region = region;self.host = service+'.'+region+'.amazonaws.com'
        self._context = context
        self._dial = dial or (lambda:socket.create_connection((self.host,443),timeout=10))
        model_path = SDK/'botocore/data'/service/VERSIONS[service]/'service-2.json.gz'
        self._model = ServiceModel(json.loads(gzip.decompress(model_path.read_bytes())))
        self._serializer = create_serializer('json');self._parser = create_parser('json')

    def _call(self,operation,parameters):
        raw = secure = connection = timer = None
        try:
            require(operation in OPERATIONS[self.service],'aws-operation-forbidden')
            model = self._model.operation_model(operation)
            serialized = self._serializer.serialize_to_request(parameters,model)
            require(serialized['method'] == 'POST' and serialized['url_path'] == '/'
                    and not serialized.get('query_string'),'aws-operation-forbidden')
            body = serialized['body'];require(type(body) is bytes and len(body) <= LIMIT,'aws-request-size')
            credential_data=self._credential_source.get() if self._credential_source else self._credential_data
            require(credential_data['expires_at'] > int(time.time())+5,'aws-credentials-expired')
            signing=(self._Credentials(credential_data['access_key_id'],credential_data['secret_access_key'],
                credential_data['session_token']) if self._credential_source else self._credentials)
            request = self._AWSRequest(method='POST',url='https://'+self.host+'/',data=body,
                                       headers=serialized['headers'])
            self._SigV4Auth(signing,self.service,self.region).add_auth(request)
            raw = self._dial();raw.settimeout(10)
            def expire():
                stream = secure or raw
                try:stream.shutdown(socket.SHUT_RDWR)
                except OSError:pass
            timer = threading.Timer(15,expire);timer.daemon = True;timer.start()
            secure = self._context.wrap_socket(raw,server_hostname=self.host)
            connection = http.client.HTTPConnection(self.host,timeout=10);connection.sock = secure
            connection.set_debuglevel(0)
            headers = dict(request.headers.items())
            headers.update({'Accept-Encoding':'identity','Connection':'close'})
            connection.request('POST','/',body=body,headers=headers)
            response = connection.getresponse()
            require(response.status == 200 or 400 <= response.status < 600,'aws-http-status')
            for name in ('Content-Length','Transfer-Encoding','Content-Type','Content-Encoding'):
                require(sum(k.lower() == name.lower() for k,_ in response.getheaders()) <= 1,'aws-http-ambiguous')
            require(not (response.getheader('Content-Length') and response.getheader('Transfer-Encoding')),'aws-http-ambiguous')
            require(response.getheader('Content-Encoding','identity').lower() == 'identity'
                    and response.getheader('Transfer-Encoding','').lower() in ('','chunked'),'aws-http-encoding')
            require(response.getheader('Content-Type','').split(';')[0].lower() in
                    ('application/json','application/x-amz-json-1.0','application/x-amz-json-1.1'),'aws-http-content-type')
            length = response.getheader('Content-Length')
            if length is not None:
                require(re.fullmatch(r'[0-9]{1,9}',length) and int(length) <= LIMIT,'aws-response-size')
            data = response.read(LIMIT+1)
            require(len(data) <= LIMIT and (length is None or len(data) == int(length)),'aws-response-size')
            strict_json(data,max_bytes=LIMIT)  # Reject duplicate/ambiguous JSON before SDK parsing.
            response_dict = {'body':data,'headers':{k.lower():v for k,v in response.getheaders()},
                             'status_code':response.status}
            result = self._parser.parse(response_dict,model.output_shape)
            if response.status != 200:
                error = result.get('Error',{}).get('Code','AwsOperationFailed')
                error_shape = self._model.shape_for_error_code(error)
                if error_shape is not None:result.update(self._parser.parse(response_dict,error_shape))
                reasons = result.get('CancellationReasons',[])
                raise AwsFailure(error,[r.get('Code','Other') for r in reasons[:100]])
            return result
        except AwsFailure:raise
        except Rejected:raise
        except Exception:
            raise Rejected('aws-unavailable') from None
        finally:
            if timer:timer.cancel()
            if connection:connection.close()
            elif secure:secure.close()
            elif raw:raw.close()

    def decrypt(self,**parameters):return self._call('Decrypt',parameters)
    def generate_data_key(self,**parameters):return self._call('GenerateDataKey',parameters)
    def get_item(self,**parameters):return self._call('GetItem',parameters)
    def put_item(self,**parameters):return self._call('PutItem',parameters)
    def transact_write_items(self,**parameters):return self._call('TransactWriteItems',parameters)
    def transact_get_items(self,**parameters):return self._call('TransactGetItems',parameters)
