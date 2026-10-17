"""
Every Breakr agent, in the order the Head Agent runs them.

To add an agent: subclass BaseBreaker, then append the class here.
"""

from Agents.Secret_breaker import SecretBreaker
from Agents.Auth_breaker import AuthBreaker
from Agents.API_breaker import APIBreaker
from Agents.Injection_breaker import InjectionBreaker
from Agents.XSS_breaker import XSSBreaker
from Agents.Config_breaker import ConfigBreaker
from Agents.Dependency_breaker import DependencyBreaker
from Agents.Crypto_breaker import CryptoBreaker
from Agents.Supabase_firebase_breaker import SupabaseFirebaseBreaker
from Agents.FileUpload_breaker import FileUploadBreaker


AGENT_REGISTRY = [
    SecretBreaker,
    AuthBreaker,
    APIBreaker,
    InjectionBreaker,
    XSSBreaker,
    ConfigBreaker,
    DependencyBreaker,
    CryptoBreaker,
    SupabaseFirebaseBreaker,
    FileUploadBreaker,
]

AGENTS_BY_NAME = {
    agent.name.lower(): agent
    for agent in AGENT_REGISTRY
}
