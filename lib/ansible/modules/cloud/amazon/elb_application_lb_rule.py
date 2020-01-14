#!/usr/bin/python
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
'''

EXAMPLES = '''
'''

RETURN = '''
'''

from ansible.module_utils.aws.core import AnsibleAWSModule
from ansible.module_utils.ec2 import boto3_conn, get_aws_connection_info, camel_dict_to_snake_dict, ec2_argument_spec, \
    boto3_tag_list_to_ansible_dict, compare_aws_tags, HAS_BOTO3

from ansible.module_utils.aws.elbv2 import ApplicationLoadBalancer, ELBListeners, ELBListener, ELBListenerRules, ELBListenerRule
from ansible.module_utils.aws.elb_utils import get_elb_listener_rules


def update_elb_listener_rules(elb_obj):
    """Update ELB listener rules. json_exit here"""

    if not elb_obj.elb:
        # ELB does not exist
        module.fail_json(msg="The load balancer you are trying to manage with name %s does not exist." % (elb_obj.elb['Name']))

    # ELB exists 
    elb_obj.update_elb_attributes()
    elb_obj.modify_elb_attributes()

    # Listeners
    listeners_obj = ELBListeners(elb_obj.connection, elb_obj.module, elb_obj.elb['LoadBalancerArn'])

    _, _, listeners_do_not_exist = listeners_obj.compare_listeners()

    # Check if the listener does not exist
    for listener_does_not_delete in listeners_do_not_exist:
        module.fail_json(msg="The load balancer does not have listener on port %s with protocol %s." % (listener_to_add['Port'], listener_to_add['Protocol']))

    # Rules of each listener
    for listener in listeners_obj.listeners:
        if 'Rules' in listener:
            rules_obj = ELBListenerRules(elb_obj.connection, elb_obj.module, elb_obj.elb['LoadBalancerArn'], listener['Rules'], listener['Port'])

            rules_to_add, rules_to_modify, rules_to_delete = rules_obj.compare_rules_based_on_rule_state()

            # Delete rules
            for rule in rules_to_delete:
                rule_obj = ELBListenerRule(elb_obj.connection, elb_obj.module, {'RuleArn': rule}, rules_obj.listener_arn)
                rule_obj.delete()
                elb_obj.changed = True

            # Add rules
            for rule in rules_to_add:
                rule_obj = ELBListenerRule(elb_obj.connection, elb_obj.module, rule, rules_obj.listener_arn)
                rule_obj.create()
                elb_obj.changed = True

            # Modify rules
            for rule in rules_to_modify:
                rule_obj = ELBListenerRule(elb_obj.connection, elb_obj.module, rule, rules_obj.listener_arn)
                rule_obj.modify()
                elb_obj.changed = True

    # Get the ELB again
    elb_obj.update()

    # Get the ELB listeners again
    listeners_obj.update()

    # Update the ELB attributes
    elb_obj.update_elb_attributes()

    # Convert to snake_case and merge in everything we want to return to the user
    snaked_elb = camel_dict_to_snake_dict(elb_obj.elb)
    snaked_elb.update(camel_dict_to_snake_dict(elb_obj.elb_attributes))
    snaked_elb['listeners'] = []
    for listener in listeners_obj.current_listeners:
        # For each listener, get listener rules
        listener['rules'] = get_elb_listener_rules(elb_obj.connection, elb_obj.module, listener['ListenerArn'])
        snaked_elb['listeners'].append(camel_dict_to_snake_dict(listener))

    # Change tags to ansible friendly dict
    snaked_elb['tags'] = boto3_tag_list_to_ansible_dict(snaked_elb['tags'])

    elb_obj.module.exit_json(changed=elb_obj.changed, **snaked_elb)

def main():

    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            name=dict(required=True, type='str'),
            listeners=dict(type='list',
                           elements='dict',
                           options=dict(
                               Protocol=dict(type='str', required=True),
                               Port=dict(type='int', required=True),
                               Rules=dict(
                                    Conditions=dict(type='list'),
                                    Priority=dict(type='int', required=True),
                                    Actions=dict(type='list'),
                                    State=dict(choices=['present', 'absent'], default='present'),
                               )
                           )
                        ),
            wait_timeout=dict(type='int'),
            wait=dict(default=False, type='bool')
        )
    )

    module = AnsibleAWSModule(argument_spec=argument_spec)

    connection = module.client('elbv2')
    connection_ec2 = module.client('ec2')

    elb = ApplicationLoadBalancer(connection, connection_ec2, module)

    update_elb_listener_rules(elb)


if __name__ == '__main__':
    main()
