from __future__ import print_function

from functools import wraps
import re
from xml.etree import ElementTree as ET
from lxml.builder import E

from libcloud.compute.base import NodeImage
from .nat_rules import NatRule

# Monkey patched into the VCloud Driver instance
import libcloud.compute.drivers.vcloud
from libcloud.compute.drivers.vcloud import \
    fixxpath, get_url_path, VCloudResponse, VCloud_1_5_Connection
from libcloud.compute.types import NodeState, MalformedResponseError
from libcloud.utils.py3 import urlencode



VM_SIZES = {
  'tiny': {
      'memory': 2048,
      'cpu': 1,
  },
  'small': {
    'memory': 4096,
    'cpu': 2,
  },
  'medium': {
    'memory': 8192,
    'cpu': 4,
  },
  'medium-high-mem': {
    'memory': 16384,
    'cpu': 4,
  },
  'large': {
    'memory': 16384,
    'cpu': 8
  },
  'large-high-mem': {
    'memory': 32768,
    'cpu': 8
  },
}



# Switch over to lxml for parsing/finding rather than xml.etree - we need the
# better xpath support
class ImprovedVCloudResponse(VCloudResponse):
    def parse_body(self):
        from lxml import etree as lxml_ET
        if len(self.body) == 0 and not self.parse_zero_length_body:
            return self.body

        try:
            body = lxml_ET.XML(self.body)
        except Exception as e:
            raise MalformedResponseError('Failed to parse XML %s' % e,
                                         body=self.body,
                                         driver=self.connection.driver)
        return body

    def parse_error(self):
        res = self.parse_body()

        return ET.tostring(res)

class ImprovedVCloud_5_1_Connection(VCloud_1_5_Connection):
    responseCls = ImprovedVCloudResponse

    def add_default_headers(self, headers):
        headers['Accept'] = 'application/*+xml;version=5.1'
        headers['x-vcloud-authorization'] = self.token
        return headers

class ImprovedVCloud_5_1_Driver(libcloud.compute.drivers.vcloud.VCloud_5_1_NodeDriver):

    connectionCls = ImprovedVCloud_5_1_Connection

    def _ex_connection_class_kwargs(self):
        return { 'timeout': 20000 }

    # The base implementation of this doesn't cope with you have a net work
    # called "Default" in every VDC - it would just pick one at random. This
    # hack lets us specify the network name as a URL and just use it as is.
    def _get_network_href(self, network_name):
        if network_name.startswith("http://") or network_name.startswith("https://"):
            return network_name
        return super(ImprovedVCloud_5_1_Driver, self)._get_network_href(network_name)


    # Based on
    # http://pubs.vmware.com/vcloud-api-1-5/api_prog/
    # GUID-843BE3AD-5EF6-4442-B864-BCAE44A51867.html

    # Mapping from vCloud API state codes to libcloud state codes
    NODE_STATE_MAP = {'-1': NodeState.UNKNOWN,
                      '0': NodeState.PENDING,
                      '1': NodeState.PENDING,
                      '2': NodeState.PENDING,
                      '3': NodeState.PENDING,
                      '4': NodeState.RUNNING,
                      '5': NodeState.RUNNING,
                      '6': NodeState.UNKNOWN,
                      '7': NodeState.UNKNOWN,
                      # Change this from TERMINATED (which means can't be started) to just STOPPED
                      '8': NodeState.STOPPED,
                      '9': NodeState.UNKNOWN,
                      '10': NodeState.UNKNOWN}


    # Pull out CPU, Memory and creator in addition to defaults.
    def _to_node(self, node_elm):
        node = super(ImprovedVCloud_5_1_Driver, self)._to_node(node_elm)

        virt_hardware = node_elm.find('.//ovf:VirtualHardwareSection', namespaces=node_elm.nsmap)

        n_cpu = 0
        n_ram = 0
        for item in virt_hardware.findall('ovf:Item', namespaces=node_elm.nsmap):

            res_type = item.findtext("{%s}ResourceType" % item.nsmap['rasd'])

            if res_type == '3': # CPU
                n_cpu = int(item.findtext('{%s}VirtualQuantity' % item.nsmap['rasd']))
            elif res_type == '4': # Memory
                n_ram = int(item.findtext('{%s}VirtualQuantity' % item.nsmap['rasd']))

        node.size = self._to_size(n_ram)
        node.size.cpus = n_cpu
        node.extra['size'] = _find_node_size(node.size)

        user = node_elm.find(fixxpath(node_elm, 'Owner/User'))
        node.extra['creator'] = user.get('name')
        return node


    # Same as base, but length of 128, not 15
    @staticmethod
    def _validate_vm_names(names):
        if names is None:
            return
        hname_re = re.compile(
            '^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9]*)[\-\.])*([A-Za-z]|[A-Za-z][A-Za-z0-9]*[A-Za-z0-9])$')  # NOQA
        for name in names:
            if len(name) > 128:
                raise ValueError(
                    'The VM name "' + name + '" is too long for the computer '
                    'name (max 30 chars allowed).')
            if not hname_re.match(name):
                raise ValueError('The VM name "' + name + '" can not be '
                                 'used. "' + name + '" is not a valid '
                                 'computer name for the VM.')


    # As a hack pass an IP address in the ipmode parameter. Until we fix
    # libcloud to support this its the only way to get the info nicely down
    # to a layer we can add support on without having to re-write the
    # entirety of create_node
    def _validate_vm_ipmode(self, vm_ipmode):
        if vm_ipmode[0] in ('MANUAL', 'POOL', 'DHCP'):
            return True
        else:
            return super(ImprovedVCloud_5_1_Driver, self)._validate_vm_ipmode(vm_ipmode)


    # Related to above manual IP mode addition
    def _change_vm_ipmode(self, vapp_or_vm_id, vm_ipmode):
        if vm_ipmode[0] is 'MANUAL':
            vm_ipmode, ip_address, network = vm_ipmode
        else:
            vm_ipmode, network = vm_ipmode
        vms = self._get_vm_elements(vapp_or_vm_id)

        for vm in vms:
            res = self.connection.request(
                '%s/networkConnectionSection' % get_url_path(vm.get('href')))
            net_conns = res.object.findall(
                fixxpath(res.object, 'NetworkConnection'))
            for c in net_conns:
                # TODO: What if we want a network other than 'default'
                # Can we pull the network out of the vm/vapp?
                c.attrib['network'] = network
                c.find(fixxpath(c, 'IpAddressAllocationMode')).text = vm_ipmode
                c.find(fixxpath(c, 'IsConnected')).text = "true"

                if vm_ipmode == 'MANUAL':
                    # This is quite hacky. We probably don't want the same IP on
                    # each interface etc.
                    # We might not have an IP node
                    ip = c.find(fixxpath(c, 'IpAddress'))
                    if ip is None:
                        ip = ET.SubElement(c, fixxpath(c, 'IpAddress'))
                        # The order of the IpAddress element matter. Has to be after this :(
                        conIdx = c.find(fixxpath(c, 'NetworkConnectionIndex'))
                        c.remove(ip)
                        c.insert(c.index(conIdx)+1, ip)
                    ip.text = ip_address


            headers = {
                'Content-Type':
                'application/vnd.vmware.vcloud.networkConnectionSection+xml'
            }

            res = self.connection.request(
                '%s/networkConnectionSection' % get_url_path(vm.get('href')),
                data=ET.tostring(res.object),
                method='PUT',
                headers=headers
            )
            self._wait_for_task_completion(res.object.get('href'))


    # New method. Set multiple metadata entries in a single request rather than
    # one req per entry
    def ex_set_metadata_entries(self, node, **kwargs):
        from xml.etree import ElementTree as ET
        """
        :param node: node
        :type node: :class:`Node`

        :param key: metadata key to be set
        :type key: ``str``

        :param value: metadata value to be set
        :type value: ``str``

        :rtype: ``None``
        """
        metadata_elem = ET.Element(
            'Metadata',
            {'xmlns': "http://www.vmware.com/vcloud/v1.5",
             'xmlns:xsi': "http://www.w3.org/2001/XMLSchema-instance"}
        )

        for key,value in kwargs.items():
            entry = ET.SubElement(metadata_elem, 'MetadataEntry')
            key_elem = ET.SubElement(entry, 'Key')
            key_elem.text = key
            value_elem = ET.SubElement(entry, 'Value')
            value_elem.text = value

        # send it back to the server
        res = self.connection.request(
            '%s/metadata' % get_url_path(node.id),
            data=ET.tostring(metadata_elem),
            headers={
                'Content-Type': 'application/vnd.vmware.vcloud.metadata+xml'
            },
            method='POST')
        self._wait_for_task_completion(res.object.get('href'))


    # Added the format parameter. Most of this function is just a duplication
    # of the super method
    def ex_query(self, type, filter=None, format='records', page=1, page_size=100, sort_asc=None,
                 sort_desc=None):
        """
        Queries vCloud for specified type. See
        http://www.vmware.com/pdf/vcd_15_api_guide.pdf for details. Each
        element of the returned list is a dictionary with all attributes from
        the record.

        :param type: type to query (r.g. user, group, vApp etc.)
        :type  type: ``str``

        :param filter: filter expression (see documentation for syntax)
        :type  filter: ``str``

        :param format: format type from query
        :type  format: ``str``

        :param page: page number
        :type  page: ``int``

        :param page_size: page size
        :type  page_size: ``int``

        :param sort_asc: sort in ascending order by specified field
        :type  sort_asc: ``str``

        :param sort_desc: sort in descending order by specified field
        :type  sort_desc: ``str``

        :rtype: ``list`` of dict
        """
        # This is a workaround for filter parameter encoding
        # the urllib encodes (name==Developers%20Only) into
        # %28name%3D%3DDevelopers%20Only%29) which is not accepted by vCloud
        params = {
            'type': type,
            'pageSize': page_size,
            'page': page,
            'format': format,
        }
        if sort_asc:
            params['sortAsc'] = sort_asc
        if sort_desc:
            params['sortDesc'] = sort_desc

        url = '/api/query?' + urlencode(params)
        if filter:
            if not filter.startswith('('):
                filter = '(' + filter + ')'
            url += '&filter=' + filter.replace(' ', '+')

        results = []
        res = self.connection.request(url)
        for elem in res.object:
            if not elem.tag.endswith('Link'):
                result = elem.attrib
                result['type'] = elem.tag.split('}')[1]
                results.append(result)
        return results


    # Print '.' while waiting rather than just being silent
    def _wait_for_task_completion(self, task_href,
                                  timeout=6000):

        import time
        from sys import stdout
        start_time = time.time()
        res = self.connection.request(get_url_path(task_href))
        status = res.object.get('status')
        while status != 'success':
            if status == 'error':
                # Get error reason from the response body
                error_elem = res.object.find(fixxpath(res.object, 'Error'))
                error_msg = "Unknown error"
                if error_elem is not None:
                    error_msg = error_elem.get('message')
                raise Exception("Error status returned by task %s.: %s"
                                % (task_href, error_msg))
            if status == 'canceled':
                raise Exception("Canceled status returned by task %s."
                                % task_href)
            if (time.time() - start_time >= timeout):
                raise Exception("Timeout (%s sec) while waiting for task %s."
                                % (timeout, task_href))

            stdout.write('.')
            stdout.flush()
            time.sleep(5)
            res = self.connection.request(get_url_path(task_href))
            status = res.object.get('status')


def get_vcloud_connection(user, org, secret, host):
    """
    Gets a connection from ImprovedVCloud_5_1_Driver and returns it each time.

    The returned value should be cached by the application.
    """
    key = '%s@%s' % (user, org)
    vcloud_conn = ImprovedVCloud_5_1_Driver(key=key, secret=secret, host=host)

    # Bug in libcloud, looking at VDCs without them being populated unless this is done.
    vcloud_conn.connection.check_org()

    return vcloud_conn


# Walk the defined sizes in the config and work out which bucket we fit into.
def _find_node_size(node_size):
    for name,size in sorted(VM_SIZES.items(), key=lambda t: t[1]):
        if node_size.ram <= size['memory'] and node_size.cpus <= size['cpu']:
            return name
    return 'xx-large-unknown'


def wait_for_private_ips(conn, node):
    import time
    from sys import stdout
    stdout.write("Waiting for private IPs to be allocated")
    stdout.flush()
    timeout = 600
    wait_period = 3
    start = time.time()
    end = start + timeout
    while time.time() < end:
        node = conn._to_node(conn.connection.request(node.id).object)

        if node.private_ips:
            return node

        stdout.write('.')
        stdout.flush()
        time.sleep(wait_period)
        continue
    raise "Exception - timed out waiting for IPs to be allocated"


def lookup_gateway_info(conn, vdc_name):
    vdcs = conn.ex_query(type='orgVdc', filter='name==' + vdc_name, format='idrecords')

    if not vdcs:
        raise "Unable to find Vdc '%s'" % vdc_name

    # We need to go from /api/vdc/<id> to /api/admin/vdc/<id>/edgeGateways
    vdc_uuid = vdcs[0]['id'].split(':')[-1]
    res = conn.connection.request( '/api/admin/vdc/%s/edgeGateways' % vdc_uuid, params={'format': 'references'} )
    gws = []
    for elem in res.object:
        if not elem.tag.endswith('Link'):
            result = elem.attrib
            result['type'] = elem.tag.split('}')[1]
            gws.append(result)

    if len(gws) > 1:
        raise "More than one EdgeGateway in VDC % - we can't cope with this yet" % vdc_name
    if len(gws) > 1:
        raise "No EdgeGateway found in VDC %" % vdc_name

    gw_uuid = gws[0]['id'].split(':')[-1]
    res = conn.connection.request("/api/admin/edgeGateway/%s" % gw_uuid)

    # xpath doesn't deal well with a empty NS prefix :(
    nsmap = res.object.nsmap
    nsmap['v'] = nsmap.pop(None)

    ifaces = res.object.xpath( ".//v:GatewayInterface", namespaces=nsmap)
    nat_rules = res.object.xpath( ".//v:NatRule", namespaces=nsmap)

    # To set up the NAT rules we need the following:
    #
    # - The UUID of the external/uplink network
    # - The UUID of the internal network
    # - The public IP to map to/from
    # - The private IP we want to forward port 22 to

    gateway = {'uuid': gw_uuid, 'networks' : {}, 'nat_rules': nat_rules}
    for el in ifaces:
        net = {}
        for chld in el:
            localname = chld.xpath('local-name()')
            if localname == 'Name':
                gateway['networks'][chld.text] = net
            if localname == 'Network':
                net['href'] = chld.get('href')
            if localname == 'InterfaceType':
                net['type'] = chld.text
            if localname == 'SubnetParticipation':
                net['ip'] = chld.xpath('*[local-name() = "IpAddress"]/text()')[0]

    return gateway


def parse_nat_rules(nat_rules):
    rules_dict = {}
    for rule in nat_rules:
        nat_rule = NatRule().from_xml(rule)
        rules_dict[nat_rule.as_key()] = nat_rule
    return rules_dict


def apply_nat_rules(conn, rules, gateway):
    root = E.EdgeGatewayServiceConfiguration(
        {
            '{http://www.w3.org/2001/XMLSchema-instance}schemaLocation':
            'http://www.vmware.com/vcloud/v1.5 http://vendor-api-url.net/v1.5/schema/master.xsd'
        },
        E.NatService(
            E.IsEnabled('true'),
            *[rule.to_xml() for rule in rules]
        ),
        xmlns='http://www.vmware.com/vcloud/v1.5',
    )

    url = '/api/admin/edgeGateway/%s/action/configureServices' % gateway['uuid']

    res = conn.connection.request(url, data=ET.tostring(root), method='POST',
        headers={'Content-Type':
        'application/vnd.vmware.admin.edgeGatewayServiceConfiguration+xml'})

    conn._wait_for_task_completion(res.object.get('href'))


def create_vm(conn, name, image, network_name, vdc, size='tiny', dnat_list=[22,]):
    print(dnat_list)
    size = VM_SIZES.get(size)

    image = NodeImage(
        id = 'https://%s/api/vAppTemplate/vappTemplate-%s' %
            ( conn.connection.host, image ),
        name = 'unkown name',
        driver = conn,
    )

    res = conn.ex_query(
        type='orgVdcNetwork',
        filter='vdcName==%s;name==%s' % ( vdc, network_name ),
        format='references'
    )
    if not res:
        raise ValueError("Cannot find network '%s' in vDC '%s'!"
            % ( network_name, vdc) )

    network_href = res[0]['href']

    net_fence='bridged'

    node = conn.create_node(
        image=image,
        name=name,
        ex_vdc=vdc,
        ex_vm_fence=net_fence,
        ex_network=network_href,
        ex_vm_memory=size['memory'],
        ex_vm_cpu=size['cpu'],
        ex_vm_names=[name,],
        ex_vm_ipmode=('POOL', network_name),
    )

    node = wait_for_private_ips(conn, node)

    # get that IP address
    internal_ip = node.private_ips[0]

    rules = {
        'dnat' : dnat_list
    }

    ss_public_ip = create_nat_rules(conn, rules, node, vdc, network_name, network_href )
    return (ss_public_ip, node)

def create_nat_rules(conn, rules, node, vdc, network_name, network_href):
    gateway = lookup_gateway_info(conn, vdc)
    external_network = None
    for k,v in gateway['networks'].items():
        if v['type'] == "uplink":
            external_network = v
    if not external_network:
        raise RuntimeError('No external_network in networks')

    internal_network = gateway['networks'].get(network_name, None)
    if not internal_network:
        raise RuntimeError('No internal_network in networks')

    # Build the DNAT dict
    network_configs = parse_nat_rules(gateway['nat_rules'])
    if not network_configs:
        standard_nat_rule = NatRule().from_dict(
                {
                    'name': 'Internal',
                    'enabled': True,
                    'original': {'ip': '10.0.0.0/8'},
                    'translated': {'ip': external_network['ip']},
                    'interface': external_network['href'],
                    'type': 'snat',
                    'id': '65537'},
                )
        network_configs[standard_nat_rule.as_key()] = standard_nat_rule

    base_id = max([int(rule['id']) for rule in network_configs.values()])
    for rule_type, ports in rules.items():
        if rule_type == "snat":
            for port in ports:
                config = NatRule()
                config.update({
                    'type': rule_type,
                    'name': "Internal",
                })
                config['interface'] = internal_network['href']
                config['translated'] = { 'ip': node.private_ips[0] }
                config['original'] = { 'ip': external_network['ip'] }
                config['desc'] = 'Outbound traffic to port %s' % port
                network_configs[config.as_key()] = config
        if rule_type == "dnat":
            for port in ports:
                config = NatRule()
                config.update({
                    'type': rule_type,
                    'name': "Public",
                })
                config['interface'] = external_network['href']
                config['original'] = {
                        'ip': external_network['ip'],
                        'port': port
                    }
                config['translated'] = {
                    'ip': node.private_ips[0],
                    'port': port
                    }
                config['desc'] = 'Incoming traffic to port %s' % port
                network_configs[config.as_key()] = config

    # Add common elements to all rules
    for rule in network_configs.values():
        if 'id' not in rule:
            rule.update({
                'enabled': True,
                'protocol': 'tcp',
                'id': int(base_id),
            })
            base_id = base_id + 1

    apply_nat_rules(conn, network_configs.values(), gateway)

    return external_network['ip']


