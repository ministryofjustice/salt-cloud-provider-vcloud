import sys
import unittest
from lxml.builder import E
from lxml import etree

# import mock
# from functools import wraps
#
import test_data
#
# USE_MOCK = True
# # USE_MOCK = False
#
# def mock_function(to_mock, *xml_list):
#     def decorator(func):
#         if not USE_MOCK:
#             return func
#
#         @wraps(func)
#         @mock.patch(to_mock)
#         def mocked_func(self, mocked):
#             mocked.urlopen().read.side_effect = xml_list
#             return func(self)
#         return mocked_func
#     return decorator
#
#

from vcloud_support.nat_rules import NatRule

class NatRulesCase(unittest.TestCase):
    def setUp(self):
        """
        This emulates the object we get from libcloud.
        """
        test_data.nat_rules_xml.seek(0) # reread each time
        self.root = etree.parse(test_data.nat_rules_xml)
        self.nsmap = {'v': 'http://www.vmware.com/vcloud/v1.5'}
        self.nat_rules = self.root.xpath( ".//v:NatRule", namespaces=self.nsmap)

    def test_from_xml(self):
        for i, rule_node in enumerate(self.nat_rules):
            rule = NatRule().from_xml(rule_node)
            self.assertEqual(rule, test_data.nat_rules_dicts[i])

    def test_to_xml(self):
        for i, rule_node in enumerate(self.nat_rules):
            rule_xml = etree.tostring(rule_node, pretty_print=True)
            # print rule_xml
            nat_rule = NatRule()
            nat_rule.from_dict(test_data.nat_rules_dicts[i])
            parsed = nat_rule.to_xml()

            for el in parsed.getchildren():
                parsed_tag = el
                orig_tag = rule_node.find('.//v:%s' % parsed_tag.tag, namespaces=self.nsmap)
                # TODO Make this search inside GatewayNatRule too
                if parsed_tag.tag != "GatewayNatRule":
                    self.assertEqual(parsed_tag.text, orig_tag.text)

    def test_from_rule(self):
        arg = {'interface': 'https://api.vcd.portal.skyscapecloud.com/api/admin/network/0c615aab-a376-45c5-afe6-46fd0ad2a0ab', 'name': 'Internal', 'translated': {'ip': '37.26.91.54'}, 'type': 'snat', 'enabled': True, 'original': {'ip': '10.0.1.100/32'}, 'id': '65538'}
        NatRule().from_dict(arg)

    def test_cmp(self):
        """
        This test takes self.nat_rule as the data that has just come from the
        server.

        It then adds two "new" rules, one that is actually new (doesn't exist)
        as we know it) and the other already exists on the server.

        Calling set() on the list of rules will call the __eq__ method on the
        NatRule class.  This will remove any duplicate objects, reducing the
        length of the rules list to 3.
        """
        additional_rules = [
            {'protocol': 'tcp', 'name': 'Public', 'enabled': True, 'original': {'ip': '37.26.91.54', 'port': '22'}, 'translated': {'ip': '10.0.1.100', 'port': '22'}, 'interface': 'https://api.vcd.portal.skyscapecloud.com/api/admin/network/0c615aab-a376-45c5-afe6-46fd0ad2a0ab', 'type': 'dnat', 'id': '65587'},
            {'name': 'Internal', 'enabled': True, 'original': {'ip': '127.0.0.1'}, 'translated': {'ip': '37.26.91.54'}, 'interface': 'https://api.vcd.portal.skyscapecloud.com/api/admin/network/0c615aab-a376-45c5-afe6-46fd0ad2a0ab', 'type': 'snat', 'id': '65538'},
        ]

        rules = []
        for rule in self.nat_rules:
            rules.append(NatRule().from_xml(rule))

        for rule in additional_rules:
            rules.append(NatRule().from_dict(rule))

        # for rule in rules:
        #     print rule

        self.assertEqual(len(rules), 4)
        self.assertEqual(len(set(rules)), 2)

    def test_as_key(self):
        rules = {}
        for rule in self.nat_rules:
            nat_rule = NatRule().from_xml(rule)
            rules[nat_rule.as_key()] = nat_rule

        rules_keys = sorted(rules.keys())
        self.assertEqual(rules_keys, ['37.26.91.54:22', '37.26.91.54:Any'])

if __name__ == "__main__":
    unittest.main()
