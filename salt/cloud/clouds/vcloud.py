import sys
import copy
import pprint
import logging
from lxml.builder import E

import salt.config as config
from saltcloud.libcloudfuncs import *   # pylint: disable-msg=W0614,W0401
from saltcloud.utils import namespaced_function

import libcloud
from libcloud.compute.base import NodeImage

from .vcloud_support.libcloud_vcloud import get_vcloud_connection, wait_for_private_ips,\
    lookup_gateway_info, apply_nat_rules, parse_nat_rules, create_vm

# Get logging started
log = logging.getLogger(__name__)


def list_nodes():
    return saltcloud.libcloudfuncs.list_nodes()


def __virtual__():
    '''
    Set up the libcloud functions and check for vCloud configurations.
    '''
    if get_configured_provider() is False:
        log.debug(
            'There is no vCloud cloud provider configuration available. Not '
            'loading module.'
        )
        return False

    log.debug('Loading vCloud cloud module')

    return True


def get_configured_provider():
    '''
    Return the first configured instance.
    '''

    return config.is_provider_configured(
        __opts__,
        __active_provider_name__ or 'vcloud',
        ('user', 'org', 'secret', 'host',)
    )


def get_opt(opt, vm_={}, default=None):
    if not vm_:
        vm_ = get_configured_provider()
    return config.get_cloud_config_value(opt, vm_, __opts__, default=default)


def get_conn(vm_={}):
    # TODO cache this
    user = get_opt('user')
    org = get_opt('org')
    secret = get_opt('secret')
    host = get_opt('host')
    return get_vcloud_connection(user, org, secret, host)


def get_password(vm_):
    '''
    Return the password to use
    '''
    return config.get_cloud_config_value(
        'password', vm_, __opts__, default=config.get_cloud_config_value(
            'passwd', vm_, __opts__, search_global=False
        ), search_global=False
    )


def create(vm_):
    conn = get_conn()
    size = get_opt('size', vm_)
    image = get_opt('image', vm_)
    vdc = get_opt('vdc', vm_)
    network = get_opt('network', vm_)
    dnat_list = get_opt('dnat', default=[])
    name = vm_['name']

    ss_public_ip, node = create_vm(
        conn,
        name,
        image,
        network,
        vdc,
        size=size,
        dnat_list=dnat_list
    )

    ssh_username = config.get_cloud_config_value(
        'ssh_username', vm_, __opts__, default='root'
    )

    ret = {}
    if config.get_cloud_config_value('deploy', vm_, __opts__) is True:
        deploy_script = script(vm_)
        deploy_kwargs = {
            'host': node.private_ips[0],
            'username': ssh_username,
            'key_filename': get_opt('private_key', vm_),
            'script': deploy_script.script,
            'name': vm_['name'],
            'tmp_dir': config.get_cloud_config_value(
                'tmp_dir', vm_, __opts__, default='/tmp/.saltcloud'
            ),
            'deploy_command': config.get_cloud_config_value(
                'deploy_command', vm_, __opts__,
                default='/tmp/.saltcloud/deploy.sh',
            ),
            'start_action': __opts__['start_action'],
            'parallel': __opts__['parallel'],
            'sock_dir': __opts__['sock_dir'],
            'conf_file': __opts__['conf_file'],
            'minion_pem': vm_['priv_key'],
            'minion_pub': vm_['pub_key'],
            'keep_tmp': __opts__['keep_tmp'],
            'preseed_minion_keys': vm_.get('preseed_minion_keys', None),
            'sudo': config.get_cloud_config_value(
                'sudo', vm_, __opts__, default=(ssh_username != 'root')
            ),
            'sudo_password': config.get_cloud_config_value(
                'sudo_password', vm_, __opts__, default=None
            ),
            'tty': config.get_cloud_config_value(
                'tty', vm_, __opts__, default=False
            ),
            'display_ssh_output': config.get_cloud_config_value(
                'display_ssh_output', vm_, __opts__, default=True
            ),
            'script_args': config.get_cloud_config_value(
                'script_args', vm_, __opts__
            ),
            'script_env': config.get_cloud_config_value('script_env', vm_, __opts__),
            'minion_conf': saltcloud.utils.minion_config(__opts__, vm_)
        }

        # Deploy salt-master files, if necessary
        if config.get_cloud_config_value('make_master', vm_, __opts__) is True:
            deploy_kwargs['make_master'] = True
            deploy_kwargs['master_pub'] = vm_['master_pub']
            deploy_kwargs['master_pem'] = vm_['master_pem']
            master_conf = saltcloud.utils.master_config(__opts__, vm_)
            deploy_kwargs['master_conf'] = master_conf

            if master_conf.get('syndic_master', None):
                deploy_kwargs['make_syndic'] = True

        deploy_kwargs['make_minion'] = config.get_cloud_config_value(
            'make_minion', vm_, __opts__, default=True
        )

        # Store what was used to the deploy the VM
        event_kwargs = copy.deepcopy(deploy_kwargs)
        del(event_kwargs['minion_pem'])
        del(event_kwargs['minion_pub'])
        del(event_kwargs['sudo_password'])
        if 'password' in event_kwargs:
            del(event_kwargs['password'])
        ret['deploy_kwargs'] = event_kwargs

        saltcloud.utils.fire_event(
            'event',
            'executing deploy script',
            'salt/cloud/{0}/deploying'.format(vm_['name']),
            {'kwargs': event_kwargs},
        )

        deployed = False
        deployed = saltcloud.utils.deploy_script(**deploy_kwargs)

        if deployed:
            log.info('Salt installed on {0}'.format(vm_['name']))
        else:
            log.error(
                'Failed to start Salt on Cloud VM {0}'.format(
                    vm_['name']
                )
            )

    log.info('Created Cloud VM {0[name]!r}'.format(vm_))
    log.debug(
        '{0[name]!r} VM creation details:\n{1}'.format(
            vm_, pprint.pformat(node.__dict__)
        )
    )

    ret.update(node.__dict__)

    saltcloud.utils.fire_event(
        'event',
        'created instance',
        'salt/cloud/{0}/created'.format(vm_['name']),
        {
            'name': vm_['name'],
            'profile': vm_['profile'],
            'provider': vm_['provider'],
        },
    )

    return ret


# TODO we shold be able to do something like this:
# script = namespaced_function(script, globals())
# however the globals don't seem to work.
def list_nodes(conn=None, call=None):
    if not conn:
        conn = get_conn()
    return saltcloud.libcloudfuncs.list_nodes(conn)

script = namespaced_function(script, globals())

