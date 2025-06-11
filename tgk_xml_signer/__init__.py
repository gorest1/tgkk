
"""TGK XML Signer — simple XMLDSig helper."""
from .signer import sign_xml
from .verifier import verify_xml_signature
__all__ = ['sign_xml', 'verify_xml_signature']
__version__ = '0.2.0'
