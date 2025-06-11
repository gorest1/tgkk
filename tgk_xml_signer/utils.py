
from lxml import etree

def load_xml(path: str) -> etree._ElementTree:
    parser = etree.XMLParser(remove_blank_text=True)
    return etree.parse(path, parser)

def write_xml(tree: etree._ElementTree, path: str) -> None:
    tree.write(path, encoding='utf-8', pretty_print=True, xml_declaration=True)
