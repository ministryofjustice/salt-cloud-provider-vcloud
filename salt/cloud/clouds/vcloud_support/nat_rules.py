from xml.etree import ElementTree as ET
from lxml.builder import E


class NatRule(dict):
    """
    A NAT Rule is a wrapper around a python Dict that adds the following:
    
    * A to_ and from_xml method that knows how to parse to/from the SkyScape XML
    * A __cmp__ method for comparing the rules to each other.
    
    It represents a single NAT rule
    """
    
    nsmap = {'v': 'http://www.vmware.com/vcloud/v1.5'}
    
    def __eq__(self, other):
        try:
            if self['type'] == 'dnat':
                self_dict = {
                    'original': self['original'],
                    'type': self['type'],
                }
                other_dict = {
                    'original': other['original'],
                    'type': other['type'],
                }
            else:
                self_dict = {
                    'translated': self['translated'],
                    'type': self['type'],
                }
                other_dict = {
                    'translated': other['translated'],
                    'type': other['type'],
                }
                
        except KeyError:
            return False
        return self_dict == other_dict

    def __hash__(self):
        return 0
    
    def as_key(self):
        if self['type'] == "dnat":
            key = "original"
        else:
            key = "translated"
        return "%s:%s" % (self[key]['ip'], self[key].get('port', 'Any'))
    
    def from_xml(self, xml_node):
        """
        Builds a rule dict from the XML etree object passed in.
        """
        # print ET.tostring(xml_node, namespaces=self.nsmap)

        self['interface'] = xml_node.xpath('.//v:Interface', namespaces=self.nsmap)[0].attrib['href']
        
        if xml_node.find('.//v:IsEnabled', namespaces=self.nsmap).text == "true":
            self['enabled'] = True
        else:
            self['enabled'] = False
            
        self['id'] = xml_node.find('.//v:Id', namespaces=self.nsmap).text
        self['type'] = xml_node.find('.//v:RuleType', namespaces=self.nsmap).text.lower()

        self['original'] = {
            'ip': xml_node.find('.//v:OriginalIp', namespaces=self.nsmap).text
        }

        self['translated'] = {
            'ip': xml_node.find('.//v:TranslatedIp', namespaces=self.nsmap).text
        }

        if self['type'] == "dnat":
            self['name'] = "Public"
            self['protocol'] = xml_node.find('.//v:Protocol', namespaces=self.nsmap).text

            original_port = xml_node.find('.//v:OriginalPort', namespaces=self.nsmap)
            if original_port is not None:
                self['original']['port'] = original_port.text

            translated_port = xml_node.find('.//v:TranslatedPort', namespaces=self.nsmap)
            if translated_port is not None:
                self['translated']['port'] = translated_port.text
        else:
            self['name'] = "Internal"
        return self
    
    def from_dict(self, rule_dict):
        self.update(rule_dict)
        return self
        
    
    def to_xml(self):
        # Build up XML children of the GatewayNatRule node. Order matters because... XML? Stupid vCloud
        rule_dict = self
        rule_children = [
            E.Interface(
                type='application/vnd.vmware.admin.network+xml',
                name=rule_dict['name'],
                href=rule_dict['interface']
            ),
            E.OriginalIp(str(rule_dict['original']['ip'])),
        ]
 
        if 'port' in rule_dict['original']:
            rule_children.append(E.OriginalPort(str(rule_dict['original']['port'])))
 
        rule_children.append(E.TranslatedIp(str(rule_dict['translated']['ip'])))
 
        if 'port' in rule_dict['translated']:
            rule_children.append(E.TranslatedPort(str(rule_dict['translated']['port'])))
 
        if rule_dict['type'] == 'dnat':
            rule_children.append(E.Protocol(str(rule_dict['protocol'])))
 
        rule_xml = E.NatRule(
            E.RuleType(rule_dict['type'].upper()),
            E.IsEnabled(str(rule_dict['enabled']).lower()),
            E.Id(str(rule_dict['id'])),
            E.GatewayNatRule(*rule_children)
        )
        
        return rule_xml