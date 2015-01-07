#!/usr/bin/env python
'''
Simple Ansible module for managing Elastic Load Balancer policies.
'''

DOCUMENTATION = '''
---
module: ec2_elb_lb_policy
short_description: manage policies on EC2 ELBs
description:
  - This module makes it possible to add or remove policies on EC2 Elastic
    Load Balancers.  It is important to note that this module does not compare
    policy configuration; the presence of the is confirmed by checking for
    the existence of the policy name.  That is, if a policy of the given name
    exists in the load balancer, it's considered present, whether or not the
    configuration matches.
version_added: "1.9"
author: Herby Gillot <herby.gillot@gmail.com>
options:
    lb_name:
        description:
          - Name of the load balancer to which to make changes to
        required: true
    policy_name:
        description:
          - Name of the policy to create or remove
        required: true
    state:
        description:
          - Desired state of the policy, or action to perform. If 'list',
            provides a listing of the names of all policies present
            in this load balancer
        choices: ['present', 'absent', 'list']
        required: true
    policy:
        description:
          - Policy definition in dictionary format.  Used when definining
            specific policy types.  This dictionary is expected to contain the
            keys 'type' and 'attributes'. The value for 'type' should be the
            desired policy type for this policy. The value for 'attributes'
            should be a dictionary of the desired policy attributes. This
            CANNOT be specified at the same time as "cookie_expiration" or
            "cookie_name".
        required: False
    cookie_expiration:
        description:
          - Used to define a session stickiness policy with the given duration.
            If set to -1, the session duration will be decided by the
            browser/user-agent.  This CANNOT be specified at the same time as
            "policy" or "cookie_name"
        required: False
    cookie_name:
        description:
          - Defines a session stickiness policy by way of an application-side
            cookie, with a cookie of the given name.  This CANNOT be specified
            at the same time as "policy" or "cookie_expiration"
        required: False
    force:
        description:
          - Always create the policy even if one by this name already exists
            in the load balancer.
        default: False
        required: False
extends_documentation_fragment: aws
notes:
  - Policy presence is determined by checking for the policy name. If a policy
    exists on the load balancer with the defined name, the module will make no
    changes, whether or not the configurations match. Use *force* if it is
    desired that the policy be overwritten.
'''

EXAMPLES = '''
  - name: "Create a policy enabling session stickiness"
    ec2_elb_lb_policy:
        lb_name: 'my-elb-1'
        policy_name: 'EnableStickySessions'
        cookie_expiration: -1
        region: 'us-west-1'
        state: 'present'

  - name:
      "Create a policy enabling session stickiness using an application cookie"
    ec2_elb_lb_policy:
        lb_name: 'my-elb-1'
        policy_name: 'EnableStickySessionsWithAppCookie'
        cookie_name: 'my_app'
        region: 'us-west-1'
        state: 'present'

  - name: "Create a policy enabling proxy protocol support on the ELB my-elb-1"
    ec2_elb_lb_policy:
      lb_name: 'my-elb-1'
      policy_name: 'EnableProxyProtocol'
      policy: {
          'type': 'ProxyProtocolPolicyType',
          'attributes': { 'ProxyProtocol': 'true' }
      }
      region: 'us-east-1'
      state: 'present'
'''

# imports #####################################################################
import boto.ec2.elb

from boto.exception import BotoServerError
from collections import Mapping
from functools import partial
from itertools import chain
from operator import attrgetter


# classes #####################################################################
class LBPolicyManager(object):
    '''
    Simple class for managing Elastic load balancer policies
    '''

    LB_POLICY_CATEGORIES = [
        'app_cookie_stickiness_policies',
        'lb_cookie_stickiness_policies',
        'other_policies',
        ]

    def __init__(self, lb_name, region, boto_params={}):
        self.lb_name = lb_name
        self.conn = connect_to_aws(boto.ec2.elb, region, **boto_params)

        if not self.lb_name:
            raise ValueError(
                'Load balancer name required as module parameter.')

    @property
    def lb(self):
        '''
        Return the boto object for this load balancer.

        Returns the load balancer if found.
        Raises ValueError if no load balancer by that name can be found.
        Raises TooManyItems if somehow too many objects are found by that name.
        '''
        lb = []

        try:
            lb = self.conn.get_all_load_balancers(
                load_balancer_names=[self.lb_name])
        except BotoServerError, e:
            if e.code == 'LoadBalancerNotFound':
                raise ValueError('Cannot find load balancer "{}"'.format(
                    self.lb_name))

        if len(lb) > 1:
            raise TooManyItems(
                'More than one load balancer found by the name "{}"'.format(
                    self.lb_name))

        return lb[0]

    @property
    def policy_map(self):
        '''
        Return a dictionary of the policies contained by this load balancer.

        Entries are in the format:
            { 'policy category': [ ...list of policy objects...] }
        '''
        get_policy_name = attrgetter('policy_name')
        get_policy_names = partial(map, get_policy_name)

        policy_map = {
            category: get_policy_names(getattr(self.lb.policies, category, []))
            for category in self.LB_POLICY_CATEGORIES}
        return policy_map

    @property
    def policy_names(self):
        '''
        Return the list of all policy names defined for this load balancer.
        '''
        return list(chain(*self.policy_map.values()))

    def create(self, name, create_call, call_arguments, overwrite=False):
        '''
        Create a new policy of the given name for this load balancer using the
        given callable, passed the specified collection of arguments.

        If overwrite is specified as True, then the policy by this name
        is deleted if it exists before attempting creation.

        Returns a dictionary indicating if anything changed and the policy's
        name.
        '''
        changed = False

        if self.has_policy(name) and overwrite:
            changed = self.delete_policy(name)

        pre = self.has_policy(name)
        try:
            create_call(name, *call_arguments)
        except BotoServerError, e:
            if e.code == 'DuplicatePolicyName':
                changed = changed or False
        post = self.has_policy(name)

        return {
            'changed': changed or bool(pre != post),
            'policy_name': name,
            'lb': self.lb_name}

    def create_policy(self, name, policy_type, policy_attributes):
        '''
        Create a policy on this load balancer with the given name,
        of the specified type, containing the given attributes.
        '''
        return self.lb.create_lb_policy(name, policy_type, policy_attributes)

    def create_cookie_stickiness_policy(self, name, expiration_period=-1):
        '''
        Create an LB side cookie stickiness policy with the specified name.
        Expiration_period if set decides session lifetimes, or if set to -1
        (or not specified), defaults to that of the browser or user-agent.
        '''
        if int(expiration_period) == -1:
            expiration_period = None

        return self.lb.create_cookie_stickiness_policy(expiration_period, name)

    def create_app_cookie_stickiness_policy(self, name, cookie_name):
        '''
        Create an ELB policy with the specified name implementing session
        stickiness using application-side cookies.  The cookies will be
        named with the given "cookie_name".
        '''
        return self.lb.create_app_cookie_stickiness_policy(cookie_name, name)

    def delete(self, name):
        '''
        Given a policy name, remove it from this load balancer.
        Returns an informational dictionary indicating if anything changed
        and the policy name.
        '''
        return {
            'changed': self.delete_policy(name),
            'policy_name': name,
            'lb': self.lb_name}

    def delete_policy(self, name):
        '''
        Delete a policy from this load balancer.
        Return True if a deletion occured, False otherwise.
        '''
        changed = False

        pre = self.has_policy(name)
        self.lb.delete_policy(name)
        post = self.has_policy(name)

        if pre != post:
            changed = True

        return changed

    def has_policy(self, name):
        '''
        Given a policy name, returns True if this load balancer currently
        has a policy by this name, False otherwise.
        '''
        return name in self.policy_names


class LBPolicyModule(object):
    '''
    ELB Policy Ansible module main class
    '''

    def __init__(self, module):

        self.lb_name = module.params.get('lb_name')
        self.policy_name = module.params.get('policy_name')
        self.desired_state = module.params.get('state')
        self.force_mode = module.params.get('force')

        self.cookie_name = module.params.get('cookie_name')
        self.cookie_expiration = module.params.get('cookie_expiration')
        self.policy = module.params.get('policy')

        self.check_params()
        self.check_policy()

        region, _, boto_params = get_aws_connection_info(module)
        self.mgr = LBPolicyManager(self.lb_name, region, boto_params)

    def check_params(self):
        '''
        Additional module params checks
        '''
        # We should only have one of policy, cookie_expiration or cookie_name
        mutex_list = ['policy', 'cookie_expiration', 'cookie_name']
        mutex_items = map(lambda i: getattr(self, i), mutex_list)

        if len(filter(None, mutex_items)) > 1:
            raise ValueError(
                'Only one of "{}" should be specified.'.format(
                    ', '.join(mutex_list)))

    def check_policy(self):
        '''
        Validate a policy specification, if one is provided.
        Raises TypeError or ValueError on invalid data.
        '''
        if self.policy is None:
            return

        if not isinstance(self.policy, Mapping) or not self.policy:
            raise TypeError(
                '''
The 'policy' paramaeter should be specified as a dictionary in the format:

{
  "type": "<policy_type>",
  "attributes": {
      "attribute1": "value1",
      "attribute2": "value2",
      ...
      }
}
                ''')

        for field in ['type', 'attributes']:
            if field not in self.policy:
                raise ValueError('Policy is missing key "{}"'.format(field))

        if not isinstance(self.policy['type'], basestring):
            raise TypeError('Policy type should be a string.')

        if not isinstance(self.policy['attributes'], Mapping):
            raise TypeError(
                'Policy attributes should be specified as a dictionary.')

    def do_action(self):
        '''
        Execute the correct action depending on the Ansible module parameters.
        Returns a module data dictionary.
        '''
        if self.desired_state == 'present':

            if self.policy:
                policy_maker = self.mgr.create_policy
                arguments = (self.policy['type'], self.policy['attributes'],)

            elif self.cookie_expiration:
                policy_maker = self.mgr.create_cookie_stickiness_policy
                arguments = (self.cookie_expiration,)

            elif self.cookie_name:
                policy_maker = self.mgr.create_app_cookie_stickiness_policy
                arguments = (self.cookie_name,)

            else:
                raise ModuleError(
                    '''
A policy type to create has not been specified, so don't know what to do...

  Please use one of:

  - policy
    > Custom policy with a specified type and attributes.

  - cookie_expiration
    > Policy for duration-based session stickiness

  - cookie_name
    > Policy for session stickiness by way of a special
      application-side cookie.

Please refer to documentation for more details.
                    ''')

            return self.mgr.create(self.policy_name,
                                   policy_maker,
                                   arguments,
                                   overwrite=self.force_mode)

        elif self.desired_state == 'absent':
            return self.mgr.delete(self.policy_name)

        elif self.desired_state == 'list':
            results = self.mgr.policy_map
            results['all'] = self.mgr.policy_names
            return {'results': results}

        else:
            raise ModuleError(
                'Unrecognized state. Expecting "present", "absent" or "list".')


# exceptions ##################################################################
class ModuleError(Exception):
    pass


class TooManyItems(ModuleError):
    pass


# defs ########################################################################
def get_ansible_module():
    ansible_arg_spec = ec2_argument_spec()
    ansible_arg_spec.update(dict(
        lb_name={'required': True},
        policy_name={'required': True},
        force={'required': False, 'type': 'bool', 'default': False},
        state={'required': True, 'choices': ['present', 'absent', 'list']},
        policy={'type': 'dict'},
        cookie_expiration={'type': 'int'},
        cookie_name={}
        )
    )

    return AnsibleModule(argument_spec=ansible_arg_spec)


def main():
    module = get_ansible_module()

    try:
        lbpolmod = LBPolicyModule(module)
        results = lbpolmod.do_action()
    except Exception, e:
        module.fail_json(msg=e.message)

    module.exit_json(**results)


# main ########################################################################
from ansible.module_utils.basic import *  # noqa
from ansible.module_utils.ec2 import *    # noqa


if __name__ == '__main__':
    main()
