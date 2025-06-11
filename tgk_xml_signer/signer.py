
from pathlib import Path
from typing import Union, Optional
from lxml import etree
from signxml import XMLSigner, methods

from .utils import load_xml, write_xml

def sign_xml(xml_input: Union[str, Path],
             key_path: Union[str, Path],
             cert_path: Union[str, Path],
             xml_output: Optional[Union[str, Path]] = None,
             reference_uri: Optional[str] = None):
    doc = load_xml(str(xml_input))
    root = doc.getroot()
    signer = XMLSigner(method=methods.enveloped,
                       signature_algorithm='rsa-sha256',
                       digest_algorithm='sha256')
    with open(key_path, 'rb') as kf, open(cert_path, 'rb') as cf:
        signed_root = signer.sign(root, key=kf.read(), cert=cf.read(),
                                  reference_uri=reference_uri)
    signed_tree = etree.ElementTree(signed_root)
    if xml_output:
        write_xml(signed_tree, str(xml_output))
    return signed_tree
