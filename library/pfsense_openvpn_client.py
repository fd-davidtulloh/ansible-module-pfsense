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
		<openvpn-client>
			<auth_user><![CDATA[admin]]></auth_user>
			<auth_pass><![CDATA[&amp;l[1N-uOAEcJ|/5]]></auth_pass>
			<vpnid>1</vpnid>
			<protocol>UDP4</protocol>
			<dev_mode>tun</dev_mode>
			<interface>wan</interface>
			<ipaddr></ipaddr>
			<local_port></local_port>
			<server_addr>52.63.16.42</server_addr>
			<server_port>1194</server_port>
			<proxy_addr></proxy_addr>
			<proxy_port></proxy_port>
			<proxy_authtype>none</proxy_authtype>
			<proxy_user></proxy_user>
			<proxy_passwd></proxy_passwd>
			<description><![CDATA[HQ]]></description>
			<mode>p2p_shared_key</mode>
			<topology>subnet</topology>
			<custom_options></custom_options>
			<shared_key>LS0tLS1CRUdJTiBPcGVuVlBOIFN0YXRpYyBrZXkgVjEtLS0tLQ0KMzVmNmJhMmRlZWUyYjZiNDBkNjFmNjI3YjgyYzRhMWENCjk2MGM1YTcwYzE3Y2I3NjRmYTY4ZDE5M2EwMDg1MDc3DQpkZjYwOGU0NmFkMDAxYWE4Y2E5YzNmZDI0YTYxOTUxNg0KMjkxMDViNGQ2NjkwNzRmZjJiODhlNDI4NzI4NDViYTUNCjE4NzM3ZjU3ZTUwMzAyZmQzYmU5NmEyODc1YzExNzgyDQo1NjI3ODE4NDFhOGMxOWU4MTkwYzMwZTJiOGUyZDdlMQ0KODhlMmFiZGRjYzBmOTY2NDk2N2U3NDlmZmE0MTllYzYNCjA0Yjk1ZmU0YTYzYWQ3MjRlM2ExOTFkZjU2NGMxYjZmDQo0Y2UxZDU4ZjM2ZTYxYWFhMTk4Y2U4MmRjYmFiY2M5OQ0KNjEwMTJjY2VkNTg1ZjZmNzdiMmI5MThhMjhkZDU2YWQNCjMzMDhlYzMzN2U1ZjNjM2E2YmU4MzQ0MTZjYzgzNmRjDQo3NGZmOWVhMWZlNDdhNDI3MTVjMTg5NjhmZDEzYTgxNA0KNDBlNTRhM2UyMzExZmVkMDk2YjBiYzJjMzQ3NzVlOGINCmY0MzkzNjBlZjVmMWNlYTJkZDAwM2ZjZTU0MWExNWU5DQplZDFjYTZkZGE3ZTIwYWMxOGQwZTZkM2NjYjk5MTg5Ng0KZGQ4MDcwOWE2ZTIwODlmNDQ4MTY2NzliZDUzYTkyNmMNCi0tLS0tRU5EIE9wZW5WUE4gU3RhdGljIGtleSBWMS0tLS0t</shared_key>
			<crypto>AES-128-CBC</crypto>
			<digest>SHA256</digest>
			<engine>none</engine>
			<tunnel_network>10.200.200.0/24</tunnel_network>
			<tunnel_networkv6></tunnel_networkv6>
			<remote_network>10.0.1.0/24</remote_network>
			<remote_networkv6></remote_networkv6>
			<use_shaper></use_shaper>
			<compression>none</compression>
			<auth-retry-none>yes</auth-retry-none>
			<passtos></passtos>
			<udp_fast_io></udp_fast_io>
			<exit_notify>none</exit_notify>
			<sndrcvbuf></sndrcvbuf>
			<route_no_pull></route_no_pull>
			<route_no_exec></route_no_exec>
			<verbosity_level>5</verbosity_level>
			<create_gw>v4only</create_gw>
			<ncp-ciphers>AES-128-GCM</ncp-ciphers>
			<ncp_enable>enabled</ncp_enable>
			<ping_method>keepalive</ping_method>
			<keepalive_interval>10</keepalive_interval>
			<keepalive_timeout>60</keepalive_timeout>
			<ping_seconds>10</ping_seconds>
			<ping_action>ping_restart</ping_action>
			<ping_action_seconds>60</ping_action_seconds>
			<inactive_seconds>0</inactive_seconds>
		</openvpn-client>

  "openvpn-client": [
    {
      "auth_user": "admin",
      "auth_pass": "&l[1N-uOAEcJ|/5",
      "vpnid": "1",
      "protocol": "UDP4",
      "dev_mode": "tun",
      "interface": "wan",
      "ipaddr": "",
      "local_port": "",
      "server_addr": "52.63.16.42",
      "server_port": "1194",
      "proxy_addr": "",
      "proxy_port": "",
      "proxy_authtype": "none",
      "proxy_user": "",
      "proxy_passwd": "",
      "description": "HQ",
      "mode": "p2p_shared_key",
      "topology": "subnet",
      "custom_options": "",
      "shared_key": "LS0tLS1CRUdJTiBPcGVuVlBOIFN0YXRpYyBrZXkgVjEtLS0tLQ0KMzVmNmJhMmRlZWUyYjZiNDBkNjFmNjI3YjgyYzRhMWENCjk2MGM1YTcwYzE3Y2I3NjRmYTY4ZDE5M2EwMDg1MDc3DQpkZjYwOGU0NmFkMDAxYWE4Y2E5YzNmZDI0YTYxOTUxNg0KMjkxMDViNGQ2NjkwNzRmZjJiODhlNDI4NzI4NDViYTUNCjE4NzM3ZjU3ZTUwMzAyZmQzYmU5NmEyODc1YzExNzgyDQo1NjI3ODE4NDFhOGMxOWU4MTkwYzMwZTJiOGUyZDdlMQ0KODhlMmFiZGRjYzBmOTY2NDk2N2U3NDlmZmE0MTllYzYNCjA0Yjk1ZmU0YTYzYWQ3MjRlM2ExOTFkZjU2NGMxYjZmDQo0Y2UxZDU4ZjM2ZTYxYWFhMTk4Y2U4MmRjYmFiY2M5OQ0KNjEwMTJjY2VkNTg1ZjZmNzdiMmI5MThhMjhkZDU2YWQNCjMzMDhlYzMzN2U1ZjNjM2E2YmU4MzQ0MTZjYzgzNmRjDQo3NGZmOWVhMWZlNDdhNDI3MTVjMTg5NjhmZDEzYTgxNA0KNDBlNTRhM2UyMzExZmVkMDk2YjBiYzJjMzQ3NzVlOGINCmY0MzkzNjBlZjVmMWNlYTJkZDAwM2ZjZTU0MWExNWU5DQplZDFjYTZkZGE3ZTIwYWMxOGQwZTZkM2NjYjk5MTg5Ng0KZGQ4MDcwOWE2ZTIwODlmNDQ4MTY2NzliZDUzYTkyNmMNCi0tLS0tRU5EIE9wZW5WUE4gU3RhdGljIGtleSBWMS0tLS0t",
      "crypto": "AES-128-CBC",
      "digest": "SHA256",
      "engine": "none",
      "tunnel_network": "10.200.210.0/24",
      "tunnel_networkv6": "",
      "remote_network": "10.0.1.0/24",
      "remote_networkv6": "",
      "use_shaper": "",
      "compression": "none",
      "auth-retry-none": "yes",
      "passtos": "",
      "udp_fast_io": "",
      "exit_notify": "none",
      "sndrcvbuf": "",
      "route_no_pull": "",
      "route_no_exec": "",
      "verbosity_level": "5",
      "create_gw": "v4only",
      "ncp-ciphers": "AES-128-GCM",
      "ncp_enable": "enabled",
      "ping_method": "keepalive",
      "keepalive_interval": "10",
      "keepalive_timeout": "60",
      "ping_seconds": "10",
      "ping_action": "ping_restart",
      "ping_action_seconds": "60",
      "inactive_seconds": "0"
    }
  ]


"server": {
            "compression": "none",
            "crypto": "AES-128-CBC",
            "description": "Ansible generated",
            "dev_mode": "tun",
            "digest": "SHA256",
            "interface": "wan",
            "local_port": "1195",
            "mode": "p2p_shared_key",
            "protocol": "UDP",
            "remote_network": "10.10.0.0/16",
            "shared_key": "IwojIDIwNDggYml0IE9wZW5WUE4gc3RhdGljIGtleQojCi0tLS0tQkVHSU4gT3BlblZQTiBTdGF0aWMga2V5IFYxLS0tLS0KMzVmNmJhMmRlZWUyYjZiNDBkNjFmNjI3YjgyYzRhMWEKOTYwYzVhNzBjMTdjYjc2NGZhNjhkMTkzYTAwODUwNzcKZGY2MDhlNDZhZDAwMWFhOGNhOWMzZmQyNGE2MTk1MTYKMjkxMDViNGQ2NjkwNzRmZjJiODhlNDI4NzI4NDViYTUKMTg3MzdmNTdlNTAzMDJmZDNiZTk2YTI4NzVjMTE3ODIKNTYyNzgxODQxYThjMTllODE5MGMzMGUyYjhlMmQ3ZTEKODhlMmFiZGRjYzBmOTY2NDk2N2U3NDlmZmE0MTllYzYKMDRiOTVmZTRhNjNhZDcyNGUzYTE5MWRmNTY0YzFiNmYKNGNlMWQ1OGYzNmU2MWFhYTE5OGNlODJkY2JhYmNjOTkKNjEwMTJjY2VkNTg1ZjZmNzdiMmI5MThhMjhkZDU2YWQKMzMwOGVjMzM3ZTVmM2MzYTZiZTgzNDQxNmNjODM2ZGMKNzRmZjllYTFmZTQ3YTQyNzE1YzE4OTY4ZmQxM2E4MTQKNDBlNTRhM2UyMzExZmVkMDk2YjBiYzJjMzQ3NzVlOGIKZjQzOTM2MGVmNWYxY2VhMmRkMDAzZmNlNTQxYTE1ZTkKZWQxY2E2ZGRhN2UyMGFjMThkMGU2ZDNjY2I5OTE4OTYKZGQ4MDcwOWE2ZTIwODlmNDQ4MTY2NzliZDUzYTkyNmMKLS0tLS1FTkQgT3BlblZQTiBTdGF0aWMga2V5IFYxLS0tLS0=",
            "topology": "subnet",
            "tunnel_network": "172.23.3.0/24",
            "vpnid": "3"
        },




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
        server=dict(required=False, type=dict),
        server_addr=dict(required=True),
        mode=dict(required=False, choices=['p2p_tls', 'p2p_shared_key', 'server_tls', 'server_user', 'server_tls_user']),
        protocol=dict(required=False, default='UDP', choices=['UDP4', 'UDP6', 'TCP4', 'TCP6', 'UDP', 'TCP']),
        dev_mode=dict(required=False, default='tun', choices=['tun', 'tap']),
        shared_key=dict(required=False), # required because we only support shared key
        descr=dict(required=False),  # Used as unique identifier
        interface=dict(required=False, default='wan'),
        port = dict(required=False, default=None), # Uses next port if not specified
        tunnel_network = dict(required=False),
        remote_network = dict(required=False, type=list), # Can be string cidr, or list of string cidrs
    )

    # Can pass server result from openvpn_server to build link to that server

    result = dict(
        changed=False,
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    params = module.params

    configuration = []
    diff = False
    updated = ""

    pfsense_check(module)

    # get config and find our entry
    descr = params['descr'] or 'Ansible generated {}'.format(params['server_addr'])
    cfg = read_config(module,'openvpn')
    index = search(cfg['openvpn-client'],'description',descr)
    base = "$config['openvpn']['openvpn-client'][" + str(index) + "]"

    if params['state'] == 'present':
        configuration.append("require_once('openvpn.inc');")

        defaults = {
            "interface": "wan",
            "verbosity_level": "5",
            "auth-retry-none": "yes",
            "ping_method": "keepalive",
            "keepalive_interval": "10",
            "keepalive_timeout": "60",
            "ping_seconds": "10",
            "ping_action": "ping_restart",
            "ping_action_seconds": "60",
            "inactive_seconds": "0"
        }

        if params['server']:
            server = params['server']

            # Extract from server and translate straight across
            extract = ["mode", "crypto", "digest", "protocol",
                       "tunnel_network", "topology", "shared_key",
                       "dev_mode", "compression"]
            opts = { k: v for k, v in server.items() if k in extract }

            opts['server_port'] = server['local_port']
            opts['server_addr'] = params['server_addr']
            opts['description'] = descr
            opts['remote_network'] = ",".join(params['remote_network'])
        else:
            module.fail_json(msg='Unsupported configuration value, server must be supplied')

        if index != '':
            configuration.append("$client['vpnid'] = '{}';".format(cfg['openvpn-client'][index]['vpnid']))
        else:
            configuration.append("$client['vpnid'] = openvpn_vpnid_next();")

        configuration += [ "$client['{}'] = '{}';".format(k,v) for k, v in {**defaults, **opts}.items() ]

        # TODO: Check for diff

        diff = True

        if diff:
            configuration.append(base + "=$client;")

    elif params['state'] == 'absent':
        if index != '':
            configuration.append("unset("+base+");")
            diff = True
    else:
        module.fail_json(msg='Incorrect state value, possible choices: absent, present(default)')


    result['phpcode'] = "\n".join(configuration)
    result['updated'] = updated

    if diff:
        post = "openvpn_resync('client', $client);\n";
        if not module.check_mode:
            write_config(module, "\n".join(configuration), post)
        result['changed'] = True

    cfg = read_config(module,'openvpn')
    result['clients'] = cfg['openvpn-client']

    if index != '':
        result['client'] = cfg['openvpn-client'][index]
    else:
        result['client'] = cfg['openvpn-client'][-1]

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()




