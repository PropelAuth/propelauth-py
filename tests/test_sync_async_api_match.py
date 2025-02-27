import pytest

from propelauth_py import Auth
from propelauth_py.async_api import AsyncAuth


# Ensure both APIs have matching functions
def test_api_methods_match():
    # Get all methods from the sync auth class
    sync_methods = [method for method in dir(Auth) if not method.startswith('_')]
    async_methods = [method for method in dir(AsyncAuth) if not method.startswith('_')]
    
    # Filter out methods that are expected to be different
    sync_methods = [m for m in sync_methods if m not in ['__class__', '__dict__', '__weakref__']]
    async_methods = [m for m in async_methods if m not in ['__class__', '__dict__', '__weakref__', 
                                                          '__aenter__', '__aexit__', '_owns_session']]
    
    # Make sure all sync methods have async counterparts
    for method in sync_methods:
        assert method in async_methods, f"Method {method} missing from AsyncAuth"
    
    # Make sure all async methods have sync counterparts
    for method in async_methods:
        assert method in sync_methods, f"Method {method} in AsyncAuth but missing from Auth"