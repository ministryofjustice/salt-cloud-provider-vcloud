import os
data_dir = os.path.dirname(__file__)
nat_rules_xml = open(os.path.join(data_dir, 'nat_rules.xml'))
nat_rules_dicts = [
    {'protocol': 'tcp', 'name': 'Public', 'enabled': True, 'original': {'ip': '37.26.91.54', 'port': '22'}, 'translated': {'ip': '10.0.1.100', 'port': '22'}, 'interface': 'https://api.vcd.portal.skyscapecloud.com/api/admin/network/0c615aab-a376-45c5-afe6-46fd0ad2a0ab', 'type': 'dnat', 'id': '65537'},
    {'name': 'Internal', 'enabled': True, 'original': {'ip': '10.0.0.0/8'}, 'translated': {'ip': '37.26.91.54'}, 'interface': 'https://api.vcd.portal.skyscapecloud.com/api/admin/network/0c615aab-a376-45c5-afe6-46fd0ad2a0ab', 'type': 'snat', 'id': '65538'},
]