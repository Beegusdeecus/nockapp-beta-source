"""Source credentials/transport are acquired only for an explicit source lookup."""
import threading
from policy import ProviderClient,require


class DeferredProvider(ProviderClient):
    def __init__(self,factory):
        require(callable(factory),'provider-factory')
        self._factory=factory;self._delegate=None;self._lock=threading.Lock();self.budget_enforced=True

    def _get(self,path):
        with self._lock:
            if self._delegate is None:
                provider=self._factory()
                require(isinstance(provider,ProviderClient) and provider.budget_enforced is True,'provider-budget-required')
                self._delegate=provider
        return self._delegate._get(path)
