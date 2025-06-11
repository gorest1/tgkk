
from pathlib import Path
from typing import Union
from signxml import XMLVerifier, InvalidSignature
from .utils import load_xml

def verify_xml_signature(xml_path: Union[str, Path],
                         cert_path: Union[str, Path]) -> bool:
    tree = load_xml(str(xml_path))
    with open(cert_path, 'rb') as cf:
        try:
            XMLVerifier().verify(tree, x509_cert=cf.read())
            return True
        except InvalidSignature:
            return False
