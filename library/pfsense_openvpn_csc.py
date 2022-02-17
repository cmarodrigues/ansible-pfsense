#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Carlos Rodrigues <cmarodrigues@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_openvpn_csc
version_added: "0.1"
author: Carlos Rodrigues (@cmarodrigues)
short_description: Manage pfSense OpenVPN client specific overrides
description:
  - Manage pfSense OpenVPN client specific overrides
notes:
options:
  name:
    description: The common name for the client certificate or the username for VPN
    required: true
    type: str
  description:
    description: The description for administrative reference
    type: str
  server_list:
    description: The common separate list of specific VPN servers
    type: str
  disable:
    description: The disable flag
    type: bool
  block:
    description: The block flag
    type: bool
  custom_options:
    description: The custom options
    type: str
  tunnel_network:
    description: The tunnel network
    type: str
  tunnel_networkv6:
    description: The tunnel ipv6 network
    type: str
  local_network:
    description: The local network
    type: str
  local_networkv6:
    description: The local ipv6 network
    type: str
  remote_network:
    description: The remote network
    type: str
  remote_networkv6:
    description: The remove ipv6 network
    type: str
  gwredir:
    description: The gateway redirect
    type: str
  push_reset:
    description: The push reset rules
    type: str
  remove_route:
    description: The remove route rule
    type: str
  dns_domain:
    description: The dns domain
    type: str
  dns_server1:
    description: The dns server1
    type: str
  dns_server2:
    description: The dns server2
    type: str
  dns_server3:
    description: The dns server3
    type: str
  dns_server4:
    description: The dns server4
    type: str
  ntp_server1:
    description: The ntp server1
    type: str
  ntp_server2:
    description: The ntp server2
    type: str
  netbios_enable:
    description: The netbios enable
    type: str
  netbios_ntype:
    description: The netbios ntype
    type: str
  netbios_scope:
    description: The netbios scope
    type: str
  wins_server1:
    description: The WINS server1
    type: str
  wins_server2:
    description: The WINS server2
    type: str
  nbdd_server1:
    description: The NBDD server1
    type: str
  state:
    description: State in which to leave the configuration
    default: present
    choices: [ "present", "absent" ]
    type: str
"""

EXAMPLES = """
- name: Create OpenVPN client configuration
  pfsense_openvpn_csc:
    name: "test"
    description: "10.0.8.1/30"
    tunnel_network: "10.0.8.1/30"
    local_network: "192.168.1.0/24,10.10.10.0/24"
    state: present

- name: Remove OpenVPN client configuration
  pfsense_openvpn_csc:
    name: "test"
    state: absent
"""

RETURN = """

"""

import base64
import re

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.pfsense.module_base import PFSenseModuleBase

CSC_ARGUMENT_SPEC = dict(
    name=dict(required=True, type='str'),
    disable=dict(type='bool'),
    description=dict(type='str'),
    server_list=dict(type='str'),
    block=dict(type='bool'),
    custom_options=dict(type='str'),
    tunnel_network=dict(type='str'),
    tunnel_networkv6=dict(type='str'),
    local_network=dict(type='str'),
    local_networkv6=dict(type='str'),
    remote_network=dict(type='str'),
    remote_networkv6=dict(type='str'),
    gwredir=dict(type='str'),
    push_reset=dict(type='str'),
    remove_route=dict(type='str'),
    dns_domain=dict(type='str'),
    dns_server1=dict(type='str'),
    dns_server2=dict(type='str'),
    dns_server3=dict(type='str'),
    dns_server4=dict(type='str'),
    ntp_server1=dict(type='str'),
    ntp_server2=dict(type='str'),
    netbios_enable=dict(type='str'),
    netbios_ntype=dict(type='str'),
    netbios_scope=dict(type='str'),
    wins_server1=dict(type='str'),
    wins_server2=dict(type='str'),
    nbdd_server1=dict(type='str'),
    state=dict(type='str', default='present', choices=['present', 'absent']),
)

CSC_PHP_COMMAND_PREFIX = """
require_once('openvpn.inc');
init_config_arr(array('openvpn', 'openvpn-csc'));
"""

# This runs after we remove the group from the config so we can't use $config
CSC_PHP_COMMAND_DEL = CSC_PHP_COMMAND_PREFIX + """

$csc = array('common_name'=>'{common_name}', 'description'=>'{description}');
$wc_msg = sprintf(gettext('Deleted OpenVPN client specific override %1$s %2$s'), $csc['common_name'], $csc['description']);
openvpn_delete_csc($csc);
write_config($wc_msg);
"""


class PFSenseOpenVPNCSCModule(PFSenseModuleBase):
    """ module managing pfsense openvpn client configuration """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return CSC_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseOpenVPNCSCModule, self).__init__(module, pfsense)
        self.name = "pfsense_openvpn_csc"
        self.root_elt = self.pfsense.get_element('openvpn')
        self.openvpn_csc = self.root_elt.findall('openvpn-csc')

    ##############################
    # params processing
    #
    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params

        if params['state'] == 'absent':
            return

    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = dict()
        self.obj = obj
        # openvpn client common name
        obj['common_name'] = params['name']

        if params['state'] == 'present':
            # other options
            for option in ['disable', 'description', 'server_list', 'block', 'custom_options',
                           'tunnel_network', 'tunnel_networkv6', 'local_network',
                           'local_networkv6', 'remote_network', 'remote_networkv6',
                           'gwredir', 'push_reset', 'remove_route', 'netbios_enable',
                           'netbios_ntype', 'netbios_scope', 'dns_domain',
                           'dns_server1', 'dns_server2', 'dns_server3', 'dns_server4',
                           'ntp_server1', 'ntp_server2', 'wins_server1', 'wins_server2', 'nbdd_server1']:
                if option in params and params[option] is not None:
                    obj[option] = params[option]

        return obj

    ##############################
    # XML processing
    #
    def _find_target(self):
        result = self.root_elt.findall("openvpn-csc[common_name='{0}']".format(self.obj['common_name']))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.module.fail_json(msg='Found multiple openvpn csc for common name {0}.'.format(self.obj['common_name']))
        else:
            return None

    def _find_this_openvpn_csc_index(self):
        return self.openvpn_csc.index(self.target_elt)

    def _find_last_openvpn_csc_index(self):
        return list(self.root_elt).index(self.openvpn_csc[len(self.openvpn_csc) - 1])

    def _create_target(self):
        """ create the XML target_elt """
        return self.pfsense.new_element('openvpn-csc')

    def _copy_and_add_target(self):
        """ populate the XML target_elt """
        obj = self.obj

        self.diff['after'] = obj
        self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        self.root_elt.insert(self._find_last_openvpn_csc_index(), self.target_elt)
        # Reset openvpn_csc list
        self.openvpn_csc = self.root_elt.findall('openvpn-csc')

    def _copy_and_update_target(self):
        """ update the XML target_elt """

        before = self.pfsense.element_to_dict(self.target_elt)
        self.diff['before'] = before

        changed = self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        self.diff['after'] = self.pfsense.element_to_dict(self.target_elt)

        return (before, changed)

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return "'" + self.obj['common_name'] + "'"

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        if before is None:
            values += self.format_cli_field(self.params, 'name')
        else:
            values += self.format_updated_cli_field(self.obj, before, 'common_name', add_comma=(values))
        return values

    ##############################
    # run
    #
    def _update(self):
        if self.params['state'] == 'present':
            # add new openvpn-csc
            return self.pfsense.phpshell("""
                require_once('openvpn.inc');
                init_config_arr(array('openvpn', 'openvpn-csc'));

                $id = {idx};
                $a_csc = &$config['openvpn']['openvpn-csc'];

                $pconfig = array('common_name'      => '{common_name}',
                                 'disable'          => '{disable}',
                                 'description'      => '{description}',
                                 'server_list'      => '{server_list}',
                                 'block'            => '{block}',
                                 'custom_options'   => '{custom_options}',
                                 'tunnel_network'   => '{tunnel_network}',
                                 'tunnel_networkv6' => '{tunnel_networkv6}',
                                 'local_network'    => '{local_network}',
                                 'local_networkv6'  => '{local_networkv6}',
                                 'remote_network'   => '{remote_network}',
                                 'remote_networkv6' => '{remote_networkv6}',
                                 'gwredir'          => '{gwredir}',
                                 'push_reset'       => '{push_reset}',
                                 'remove_route'     => '{remove_route}',
                                 'dns_domain'       => '{dns_domain}',
                                 'dns_server1'      => '{dns_server1}',
                                 'dns_server2'      => '{dns_server2}',
                                 'dns_server3'      => '{dns_server3}',
                                 'dns_server4'      => '{dns_server4}',
                                 'ntp_server1'      => '{ntp_server1}',
                                 'ntp_server2'      => '{ntp_server2}',
                                 'netbios_enable'   => '{netbios_enable}',
                                 'netbios_ntype'    => '{netbios_ntype}',
                                 'netbios_scope'    => '{netbios_scope}',
                                 'wins_server1'     => '{wins_server1}',
                                 'wins_server2'     => '{wins_server2}',
                                 'nbdd_server1'     => '{nbdd_server1}' );

                /* Create configuration object */
                $csc = array('common_name' => $pconfig['common_name']);
                if (!empty($pconfig['disable']) && ($pconfig['disable']=='true')) {{
                    $csc[$field] = true;
                }}
                foreach( array( 'description', 'server_list', 'block', 'custom_options',
                            'tunnel_network', 'tunnel_networkv6', 'local_network',
                            'local_networkv6', 'remote_network', 'remote_networkv6',
                            'gwredir', 'push_reset', 'remove_route', 'netbios_enable',
                            'netbios_ntype', 'netbios_scope', 'dns_domain',
                            'dns_server1', 'dns_server2', 'dns_server3', 'dns_server4',
                            'ntp_server1', 'ntp_server2', 'wins_server1', 'wins_server2', 'nbdd_server1' ) as $field ){{
                    if (!empty($pconfig[$field]) && ($pconfig[$field]!=='None')) {{
                        $csc[$field] = $pconfig[$field];
                    }}
                }}

                if (isset($id) && $a_csc[$id]) {{
                    $old_csc = $a_csc[$id];
                    $a_csc[$id] = $csc;
                    $wc_msg = sprintf(gettext('Updated OpenVPN client specific override %1$s %2$s'), $csc['common_name'], $csc['description']);
                }} else {{
                    $a_csc[] = $csc;
                    $wc_msg = sprintf(gettext('Added OpenVPN client specific override %1$s %2$s'), $csc['common_name'], $csc['description']);
                }}

                if (!empty($old_csc['common_name'])) {{
                    openvpn_delete_csc($old_csc);
                }}
                openvpn_resync_csc($csc);
                write_config($wc_msg);""".format(idx=self._find_this_openvpn_csc_index(),
                                                 common_name=self.target_elt.find('common_name').text,
                                                 disable=self.params['disable'],
                                                 description=self.params['description'],
                                                 server_list=self.params['server_list'],
                                                 block=self.params['block'],
                                                 custom_options=self.params['custom_options'],
                                                 tunnel_network=self.params['tunnel_network'],
                                                 tunnel_networkv6=self.params['tunnel_networkv6'],
                                                 local_network=self.params['local_network'],
                                                 local_networkv6=self.params['local_networkv6'],
                                                 remote_network=self.params['remote_network'],
                                                 remote_networkv6=self.params['remote_networkv6'],
                                                 gwredir=self.params['gwredir'],
                                                 push_reset=self.params['push_reset'],
                                                 remove_route=self.params['remove_route'],
                                                 dns_domain=self.params['dns_domain'],
                                                 dns_server1=self.params['dns_server1'],
                                                 dns_server2=self.params['dns_server2'],
                                                 dns_server3=self.params['dns_server3'],
                                                 dns_server4=self.params['dns_server4'],
                                                 ntp_server1=self.params['ntp_server1'],
                                                 ntp_server2=self.params['ntp_server2'],
                                                 netbios_enable=self.params['netbios_enable'],
                                                 netbios_ntype=self.params['netbios_ntype'],
                                                 netbios_scope=self.params['netbios_scope'],
                                                 wins_server1=self.params['wins_server1'],
                                                 wins_server2=self.params['wins_server2'],
                                                 nbdd_server1=self.params['nbdd_server1']))
        else:
            return self.pfsense.phpshell(CSC_PHP_COMMAND_DEL.format(common_name=self.obj['common_name'], description=self.obj['description']))

    def _pre_remove_target_elt(self):
        self.diff['after'] = {}
        if self.target_elt is not None:
            self.diff['before'] = self.pfsense.element_to_dict(self.target_elt)

            # Store description for _update()
            self.obj['description'] = self.target_elt.find('description').text

            self.openvpn_csc.remove(self.target_elt)
        else:
            self.diff['before'] = {}


def main():
    module = AnsibleModule(
        argument_spec=CSC_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseOpenVPNCSCModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
