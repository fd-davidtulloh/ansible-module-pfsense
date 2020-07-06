#!/usr/bin/python
# vim: set expandtab:

# Copyright: (c) 2020, David Tulloh <david.tulloh@fifthdomain.com.au>
# Copyright: (c) 2018, David Beveridge <dave@bevhost.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: pfsense_openvpn

short_description: Loads a firewall filter rule into pfSense

description:
It's expected it would normally be used with a list of rules 
exported as xml from a source firewall then converted to yaml
See list and single useage examples below

However, it could be used in singularly with a rule provided manually.

version_added: "2.7"


author:
    - David Beveridge (@bevhost)

notes:
Ansible is located in an different place on BSD systems such as pfsense.
You can create a symlink to the usual location like this

ansible -m raw -a "/bin/ln -s /usr/local/bin/python2.7 /usr/bin/python" -k -u root mybsdhost1

Alternatively, you could use an inventory variable

[fpsense:vars]
ansible_python_interpreter=/usr/local/bin/python2.7

'''

EXAMPLES = '''
# example_firewall.yml playbook
  vars_files:
    - roles/example_firewall/vars/rules.yml
  tasks:
    - pfsense_filter_rules:
        state: "{{ item.state | default('present') }}"
        tracker: "{{ item.tracker }}"
        type: "{{ item.type | default('pass') }}"
        interface: "{{ item.interface | default('lan') }}"
        ipprotocol: "{{ item.ipprototcol | default('inet') }}"
        direction: "{{ item.direction | default('any') }}"
        floating: "{{ item.floating | default(omit) }}"
        statetype: "{{ item.statetype | default('keep state') }}"
        protocol: "{{ item.protocol | default(omit) }}"
        source: "{{ item.source | default(dict(any='')) }}"
        destination: "{{ item.destination | default(dict(any='')) }}"
      with_items: "{{ fw_filter }}"

# roles/example_firewall/tasks/main.yml
- pfsense_filter_rules:
    type: pass
    tracker: 1542170888
    ipprotocol: inet
    protocol: tcp
    interface: lan
    direction: any
    statetype: "keep state"
    source:
      any: ""
    destination:
      network: "(self)"
      port: 443

'''

XML = '''
	<openvpn>
		<openvpn-server>
			<vpnid>1</vpnid>
			<disable></disable>
			<mode>server_user</mode>
			<authmode>Local Database</authmode>
			<protocol>UDP</protocol>
			<dev_mode>tun</dev_mode>
			<interface>wan</interface>
			<ipaddr></ipaddr>
			<local_port>1194</local_port>
			<description><![CDATA[Netgate Auto Remote Access VPN]]></description>
			<custom_options>push &quot;route-ipv6 0::0/1 vpn_gateway&quot;;push &quot;route-ipv6 8000::0/1 vpn_gateway&quot;;</custom_options>
			<caref>5efefd4a1a317</caref>
			<crlref></crlref>
			<certref>5efefd4a32adc</certref>
			<dh_length>1024</dh_length>
			<ecdh_curve>none</ecdh_curve>
			<cert_depth>1</cert_depth>
			<crypto>AES-128-CBC</crypto>
			<digest>SHA256</digest>
			<engine>none</engine>
			<tunnel_network>172.24.42.0/24</tunnel_network>
			<tunnel_networkv6>fd6f:826b:ed1e::0/64</tunnel_networkv6>
			<remote_network></remote_network>
			<remote_networkv6></remote_networkv6>
			<gwredir>yes</gwredir>
			<gwredir6></gwredir6>
			<local_network></local_network>
			<local_networkv6></local_networkv6>
			<maxclients></maxclients>
			<compression>yes</compression>
			<compression_push></compression_push>
			<passtos></passtos>
			<client2client></client2client>
			<dynamic_ip></dynamic_ip>
			<topology>subnet</topology>
			<serverbridge_dhcp></serverbridge_dhcp>
			<serverbridge_interface>none</serverbridge_interface>
			<serverbridge_routegateway></serverbridge_routegateway>
			<serverbridge_dhcp_start></serverbridge_dhcp_start>
			<serverbridge_dhcp_end></serverbridge_dhcp_end>
			<dns_server1>172.24.42.1</dns_server1>
			<dns_server2></dns_server2>
			<dns_server3></dns_server3>
			<dns_server4></dns_server4>
			<username_as_common_name><![CDATA[enabled]]></username_as_common_name>
			<exit_notify>none</exit_notify>
			<sndrcvbuf></sndrcvbuf>
			<netbios_enable></netbios_enable>
			<netbios_ntype>0</netbios_ntype>
			<netbios_scope></netbios_scope>
			<create_gw>v4only</create_gw>
			<verbosity_level>5</verbosity_level>
			<duplicate_cn></duplicate_cn>
			<ncp-ciphers>AES-128-GCM</ncp-ciphers>
			<ncp_enable>enabled</ncp_enable>
			<ping_method>keepalive</ping_method>
			<keepalive_interval>10</keepalive_interval>
			<keepalive_timeout>60</keepalive_timeout>
			<ping_seconds>10</ping_seconds>
			<ping_push></ping_push>
			<ping_action>ping_restart</ping_action>
			<ping_action_seconds>60</ping_action_seconds>
			<ping_action_push></ping_action_push>
			<inactive_seconds>0</inactive_seconds>
		</openvpn-server>

		<openvpn-server>
			<vpnid>2</vpnid>
			<mode>p2p_shared_key</mode>
			<protocol>UDP4</protocol>
			<dev_mode>tun</dev_mode>
			<interface>opt1</interface>
			<ipaddr></ipaddr>
			<local_port>1194</local_port>
			<description></description>
			<custom_options>push &quot;route 10.0.1.0 255.255.255.0&quot;;</custom_options>
			<shared_key>LS0tLS1CRUdJTiBPcGVuVlBOIFN0YXRpYyBrZXkgVjEtLS0tLQ0KMzVmNmJhMmRlZWUyYjZiNDBkNjFmNjI3YjgyYzRhMWENCjk2MGM1YTcwYzE3Y2I3NjRmYTY4ZDE5M2EwMDg1MDc3DQpkZjYwOGU0NmFkMDAxYWE4Y2E5YzNmZDI0YTYxOTUxNg0KMjkxMDViNGQ2NjkwNzRmZjJiODhlNDI4NzI4NDViYTUNCjE4NzM3ZjU3ZTUwMzAyZmQzYmU5NmEyODc1YzExNzgyDQo1NjI3ODE4NDFhOGMxOWU4MTkwYzMwZTJiOGUyZDdlMQ0KODhlMmFiZGRjYzBmOTY2NDk2N2U3NDlmZmE0MTllYzYNCjA0Yjk1ZmU0YTYzYWQ3MjRlM2ExOTFkZjU2NGMxYjZmDQo0Y2UxZDU4ZjM2ZTYxYWFhMTk4Y2U4MmRjYmFiY2M5OQ0KNjEwMTJjY2VkNTg1ZjZmNzdiMmI5MThhMjhkZDU2YWQNCjMzMDhlYzMzN2U1ZjNjM2E2YmU4MzQ0MTZjYzgzNmRjDQo3NGZmOWVhMWZlNDdhNDI3MTVjMTg5NjhmZDEzYTgxNA0KNDBlNTRhM2UyMzExZmVkMDk2YjBiYzJjMzQ3NzVlOGINCmY0MzkzNjBlZjVmMWNlYTJkZDAwM2ZjZTU0MWExNWU5DQplZDFjYTZkZGE3ZTIwYWMxOGQwZTZkM2NjYjk5MTg5Ng0KZGQ4MDcwOWE2ZTIwODlmNDQ4MTY2NzliZDUzYTkyNmMNCi0tLS0tRU5EIE9wZW5WUE4gU3RhdGljIGtleSBWMS0tLS0t</shared_key>
			<crypto>AES-128-CBC</crypto>
			<digest>SHA256</digest>
			<engine>none</engine>
			<tunnel_network>10.200.200.0/24</tunnel_network>
			<tunnel_networkv6></tunnel_networkv6>
			<remote_network>10.10.1.0/24</remote_network>
			<remote_networkv6></remote_networkv6>
			<gwredir></gwredir>
			<gwredir6></gwredir6>
			<local_network></local_network>
			<local_networkv6></local_networkv6>
			<maxclients></maxclients>
			<compression>none</compression>
			<compression_push></compression_push>
			<passtos></passtos>
			<client2client></client2client>
			<dynamic_ip></dynamic_ip>
			<topology>subnet</topology>
			<serverbridge_dhcp></serverbridge_dhcp>
			<serverbridge_interface>none</serverbridge_interface>
			<serverbridge_routegateway></serverbridge_routegateway>
			<serverbridge_dhcp_start></serverbridge_dhcp_start>
			<serverbridge_dhcp_end></serverbridge_dhcp_end>
			<username_as_common_name><![CDATA[disabled]]></username_as_common_name>
			<exit_notify>none</exit_notify>
			<sndrcvbuf></sndrcvbuf>
			<netbios_enable></netbios_enable>
			<netbios_ntype>0</netbios_ntype>
			<netbios_scope></netbios_scope>
			<create_gw>both</create_gw>
			<verbosity_level>5</verbosity_level>
			<ncp-ciphers>AES-128-GCM</ncp-ciphers>
			<ncp_enable>disabled</ncp_enable>
			<ping_method>keepalive</ping_method>
			<keepalive_interval>10</keepalive_interval>
			<keepalive_timeout>60</keepalive_timeout>
			<ping_seconds>10</ping_seconds>
			<ping_push></ping_push>
			<ping_action>ping_restart</ping_action>
			<ping_action_seconds>60</ping_action_seconds>
			<ping_action_push></ping_action_push>
			<inactive_seconds>0</inactive_seconds>
		</openvpn-server>
	</openvpn>


{
  "openvpn-server": [
    {
      "vpnid": "1",
      "disable": "",
      "mode": "server_user",
      "authmode": "Local Database",
      "protocol": "UDP",
      "dev_mode": "tun",
      "interface": "wan",
      "ipaddr": "",
      "local_port": "1194",
      "description": "Netgate Auto Remote Access VPN",
      "custom_options": "push \"route-ipv6 0::0/1 vpn_gateway\";push \"route-ipv6 8000::0/1 vpn_gateway\";",
      "caref": "5efefd4a1a317",
      "crlref": "",
      "certref": "5efefd4a32adc",
      "dh_length": "1024",
      "ecdh_curve": "none",
      "cert_depth": "1",
      "crypto": "AES-128-CBC",
      "digest": "SHA256",
      "engine": "none",
      "tunnel_network": "172.24.42.0/24",
      "tunnel_networkv6": "fd6f:826b:ed1e::0/64",
      "remote_network": "",
      "remote_networkv6": "",
      "gwredir": "yes",
      "gwredir6": "",
      "local_network": "",
      "local_networkv6": "",
      "maxclients": "",
      "compression": "yes",
      "compression_push": "",
      "passtos": "",
      "client2client": "",
      "dynamic_ip": "",
      "topology": "subnet",
      "serverbridge_dhcp": "",
      "serverbridge_interface": "none",
      "serverbridge_routegateway": "",
      "serverbridge_dhcp_start": "",
      "serverbridge_dhcp_end": "",
      "dns_server1": "172.24.42.1",
      "dns_server2": "",
      "dns_server3": "",
      "dns_server4": "",
      "username_as_common_name": "enabled",
      "exit_notify": "none",
      "sndrcvbuf": "",
      "netbios_enable": "",
      "netbios_ntype": "0",
      "netbios_scope": "",
      "create_gw": "v4only",
      "verbosity_level": "5",
      "duplicate_cn": "",
      "ncp-ciphers": "AES-128-GCM",
      "ncp_enable": "enabled",
      "ping_method": "keepalive",
      "keepalive_interval": "10",
      "keepalive_timeout": "60",
      "ping_seconds": "10",
      "ping_push": "",
      "ping_action": "ping_restart",
      "ping_action_seconds": "60",
      "ping_action_push": "",
      "inactive_seconds": "0"
    },
    {
      "vpnid": "2",
      "mode": "p2p_shared_key",
      "protocol": "UDP4",
      "dev_mode": "tun",
      "interface": "opt1",
      "ipaddr": "",
      "local_port": "1194",
      "description": "",
      "custom_options": "push \"route 10.0.1.0 255.255.255.0\";",
      "shared_key": "LS0tLS1CRUdJTiBPcGVuVlBOIFN0YXRpYyBrZXkgVjEtLS0tLQ0KMzVmNmJhMmRlZWUyYjZiNDBkNjFmNjI3YjgyYzRhMWENCjk2MGM1YTcwYzE3Y2I3NjRmYTY4ZDE5M2EwMDg1MDc3DQpkZjYwOGU0NmFkMDAxYWE4Y2E5YzNmZDI0YTYxOTUxNg0KMjkxMDViNGQ2NjkwNzRmZjJiODhlNDI4NzI4NDViYTUNCjE4NzM3ZjU3ZTUwMzAyZmQzYmU5NmEyODc1YzExNzgyDQo1NjI3ODE4NDFhOGMxOWU4MTkwYzMwZTJiOGUyZDdlMQ0KODhlMmFiZGRjYzBmOTY2NDk2N2U3NDlmZmE0MTllYzYNCjA0Yjk1ZmU0YTYzYWQ3MjRlM2ExOTFkZjU2NGMxYjZmDQo0Y2UxZDU4ZjM2ZTYxYWFhMTk4Y2U4MmRjYmFiY2M5OQ0KNjEwMTJjY2VkNTg1ZjZmNzdiMmI5MThhMjhkZDU2YWQNCjMzMDhlYzMzN2U1ZjNjM2E2YmU4MzQ0MTZjYzgzNmRjDQo3NGZmOWVhMWZlNDdhNDI3MTVjMTg5NjhmZDEzYTgxNA0KNDBlNTRhM2UyMzExZmVkMDk2YjBiYzJjMzQ3NzVlOGINCmY0MzkzNjBlZjVmMWNlYTJkZDAwM2ZjZTU0MWExNWU5DQplZDFjYTZkZGE3ZTIwYWMxOGQwZTZkM2NjYjk5MTg5Ng0KZGQ4MDcwOWE2ZTIwODlmNDQ4MTY2NzliZDUzYTkyNmMNCi0tLS0tRU5EIE9wZW5WUE4gU3RhdGljIGtleSBWMS0tLS0t",
      "crypto": "AES-128-CBC",
      "digest": "SHA256",
      "engine": "none",
      "tunnel_network": "10.200.200.0/24",
      "tunnel_networkv6": "",
      "remote_network": "10.10.1.0/24",
      "remote_networkv6": "",
      "gwredir": "",
      "gwredir6": "",
      "local_network": "",
      "local_networkv6": "",
      "maxclients": "",
      "compression": "none",
      "compression_push": "",
      "passtos": "",
      "client2client": "",
      "dynamic_ip": "",
      "topology": "subnet",
      "serverbridge_dhcp": "",
      "serverbridge_interface": "none",
      "serverbridge_routegateway": "",
      "serverbridge_dhcp_start": "",
      "serverbridge_dhcp_end": "",
      "username_as_common_name": "disabled",
      "exit_notify": "none",
      "sndrcvbuf": "",
      "netbios_enable": "",
      "netbios_ntype": "0",
      "netbios_scope": "",
      "create_gw": "both",
      "verbosity_level": "5",
      "ncp-ciphers": "AES-128-GCM",
      "ncp_enable": "disabled",
      "ping_method": "keepalive",
      "keepalive_interval": "10",
      "keepalive_timeout": "60",
      "ping_seconds": "10",
      "ping_push": "",
      "ping_action": "ping_restart",
      "ping_action_seconds": "60",
      "ping_action_push": "",
      "inactive_seconds": "0"
    },
    ""
  ]
}


'''

RETURN = '''
filter_rules:
    description: dict containing current filter rules
debug:
    description: Any debug messages for unexpected input types
    type: str
phpcode:
    description: Actual PHP Code sent to pfSense PHP Shell
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.pfsense import write_config, read_config, search, pfsense_check, validate, isstr

import base64


def run_module():

    module_args = dict(
        state=dict(required=False, default='present', choices=['present', 'absent', 'disabled']),
        mode=dict(required=True, choices=['p2p_tls', 'p2p_shared_key', 'server_tls', 'server_user', 'server_tls_user']),
        protocol=dict(required=False, default='UDP', choices=['UDP4', 'UDP6', 'TCP4', 'TCP6', 'UDP', 'TCP']),
        dev_mode=dict(required=False, default='tun', choices=['tun', 'tap']),
        shared_key=dict(required=True), # required because we only support shared key
        descr=dict(required=True),  # Used as unique identifier
        interface=dict(required=False, default='wan'),
        port = dict(required=False, default=None), # Uses next port if not specified
        tunnel_network = dict(required=False),
        remote_network = dict(required=False, type=list), # Can be string cidr, or list of string cidrs
    )

    result = dict(
        changed=False,
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    params = module.params

    if params['mode'] != 'p2p_shared_key':
        module.fail_json(msg='Unsupported mode value, possible choices: p2p_shared_key')
        # TODO: Should support other options one day

    configuration = ""
    diff = False
    updated = ""

    pfsense_check(module)

    # get config and find our entry
    cfg = read_config(module,'openvpn')
    index = search(cfg['openvpn-server'],'description',params['descr'])

    base = "$config['openvpn']['openvpn-server'][" + str(index) + "]"

    # TODO: Update empty params from existing server - if it exists
    # TODO: Proper diff

    if params['state'] == 'present':
        configuration += "require_once('openvpn.inc');\n"

        if index != '':
            configuration += "$server['vpnid'] = '" + cfg['openvpn-server'][index]['vpnid'] + "';\n"
        else:
            configuration += "$server['vpnid'] = openvpn_vpnid_next();\n"

        if params['port']:
            configuration += "$server['local_port'] = '" + params['port'] + "';\n"
        else:
            configuration += "$server['local_port'] = openvpn_port_next(" + params['protocol'] + ", " + params['interface']+ ");\n"

        configuration += "$server['mode'] = '" + params['mode'] + "';\n"
        configuration += "$server['protocol'] = '" + params['protocol'] + "';\n"
        configuration += "$server['dev_mode'] = '" + params['dev_mode'] + "';\n"
        configuration += "$server['interface'] = '" + params['interface'] + "';\n"
        configuration += "$server['description'] = '" + params['descr'] + "';\n"
        configuration += "$server['crypto'] = 'AES-128-CBC';\n"
        configuration += "$server['digest'] = 'SHA256';\n"
        configuration += "$server['compression'] = 'none';\n"
        configuration += "$server['topology'] = 'subnet';\n"

        if params['tunnel_network']:
            configuration += "$server['tunnel_network'] = '" + params['tunnel_network']+ "';\n"
        elif index != '':
            configuration += "$server['tunnel_network'] = '172.23."+ cfg['openvpn-server'][index]['vpnid'] + ".0/24';\n"
        else:
            configuration += "$server['tunnel_network'] = '172.23.' . openvpn_vpnid_next() . '.0/24';\n"

        if type(params['remote_network']) is list:
            configuration += "$server['remote_network'] = '" + ",".join(params['remote_network']) + "';\n"
        elif params['remote_network']:
            configuration += "$server['remote_network'] = '" + params['remote_network'] + "';\n"

        configuration += "$server['shared_key'] = '" + base64.b64encode(str.encode(params['shared_key'])).decode("utf-8") + "';\n"


        diff = True

        if diff:
            configuration += base + "=$server;\n"

    elif params['state'] == 'absent':
        if index != '':
            configuration += "unset("+base+");\n"
            diff = True
    else:
        module.fail_json(msg='Incorrect state value, possible choices: absent, present(default)')


    result['phpcode'] = configuration
    result['updated'] = updated

    if module.check_mode:
        module.exit_json(**result)

    if diff:
        post = "openvpn_resync('server', $server);\nopenvpn_resync_csc_all();\n";
        write_config(module, configuration, post)
        result['changed'] = True

    cfg = read_config(module,'openvpn')
    result['servers'] = cfg['openvpn-server']

    if index != '':
        result['server'] = cfg['openvpn-server'][index]
    else:
        result['server'] = cfg['openvpn-server'][-1]

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()




