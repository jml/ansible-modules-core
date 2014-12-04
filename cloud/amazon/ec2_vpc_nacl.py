#!/usr/bin/env python
DOCUMENTATION = '''
---
module: ec2_vpc_nacl
short_description: create/modify/associate/delete AWS VPC network ACLs.
description:
    - This module can create, modify or remove VPC network ACLs.
    - Can additionally associate/disassociate VPC subnets to network ACLs.
version_added: 1.8
options:
  nacl:
    description:
      - An identifier (ACL ID, CIDR, tagged name) identifying a network ACL.
      - If this parameter isn't specified, then a ruleset, if present, will be used to match a NACL with the same rules.
    required: false
  name:
    description:
      - Alias, same as 'nacl'
  vpc:
    description:
      - An identifer (VPC ID, CIDR, tagged name) identifying the VPC.
      - This is the VPC containing the network ACL of interest.
      - This parameter is useful for disambiguating a network ACL, especially when using a non-specific NACL identifer, such as name, which could be shared by multiple ACLs over different VPCs.
    required: false
  vpc_id:
    description:
      - Alias for 'vpc'
  egress:
    description:
      - A list of rules for outgoing traffic.
      - Each rule can be specified as a dictionary or list.
      - Refer to examples or notes below for information on defining rules.
    required: false
  ingress:
    description:
      - List of rules for incoming traffic.
      - Each rule can be specified as a dictionary or list.
      - Refer to examples or notes below for information on defining rules.
    required: false
  rules:
    description:
      - Alias for 'ingress'
  rules_egress:
    description:
      - Alias for 'egress'
  region:
    description:
      - The EC2 region to connect to.  Usually should be specified.
    required: false
    default: null
    aliases: [ ec2_region ]
  subnets:
    description:
      - The list of subnets that should be associated with the specified network ACL.
      - This is the list of subnets that are associated back to the default network ACL when in disassociation mode (state is 'dissasociated').
      - Must be specified as a list
      - Each subnet can be specified as subnet ID, CIDR or its tagged name.
    required: false
  tags:
    description:
      - Dictionary of tags to look for and apply when creating a network ACL.
    required: false
  purge_rules:
    description:
      - If specified and set to True, removes all rules if both egress and ingress are empty or not specified.
    default: False
  use_default_nacl:
    description:
      - If specified and set to True, the default NACL for a VPC will be used.
      - Requires that the VPC to be specified.
      - Cannot be specified at the same time as the 'nacl' parameter.
    default: False
  state:
    description:
      - If 'present' and the NACL & egress/ingress rulesets are specified, modifies the ACL to match the rules defined in the rulesets.
      - If 'present' and no NACL identifier is provided, but egress/ingress rulesets are, will create a new network ACL matching the rulesets.
      - If 'present' or 'associated' and subnets are listed, ensures that these subnets are associated with the identified/created network ACL.
      - If 'disassociated' and a list of subnets is provided, ensures that these subnets are disassociated with any user-defined NACLs, and re-associated with the default NACL for their respective VPC.
      - If 'absent', disassociates any subnets associated with the specified network ACL, and then ensures it no longer exists.
      - If 'list', list all network ACLs found.  Restricts listing to a particular VPC is VPC is specified.
    required: false
    choices: ['present', 'absent', 'associated', 'disassociated', 'list']
    default: present

extends_documentation_fragment: aws
author: Herby Gillot <herby.gillot@gmail.com>
notes:
  - Network ACLs are located first by the 'nacl' identifier, and then if that isn't found or specified, locates by ruleset (if specified).  The network ACL used will be the one whose egress and ingress rules match the specified egress and ingress rules exactly (excluding the default egress/ingress rules).
  - You can refer to most things (network ACLs, VPCs, subnets) by their name tag, CIDR block or actual resource ID (VPC ID, subnet ID...).
  - If disassociating, VPC or NACL does not need to be specified, only the list of subnets that you want to reset back to the default network ACL.
  - If egress and ingress rules are not specified, then the network ACL will not be modified.  If you want all rules removed to match an empty ingress and egress ruleset, set purge_rules to True.
  - ACL rule fields are rule_number, protocol (all, icmp, udp, tcp), rule_action (allow/deny), cidr_block, icmp_code, icmp_type, and port_range_from + port_range_to.  icmp_code and _type need only be specified if protocol is set to 'icmp'.  port_range_from and port_range_to should be specified if protocol is 'tcp' or 'udp'. Port numbers (port_range_from, port_range_to) can be specified as "max" to mean the maximum TCP/UDP port number.
'''

EXAMPLES = '''

# Create and a network ACL that allows SSH and HTTP in, and all traffic out.
# Ensure that the subnets named 'prod-dmz-1' and 'prod-dmz-2' are associated
# with this ACL.
- name: "Create and associate production DMZ network ACL"
  ec2_vpc_nacl:
      vpc: 'prod'
      nacl: 'prod-dmz'
      region: 'us-east-1'
      subnets: ['prod-dmz-1', 'prod-dmz-2']
      ingress: [
          # rule no, protocol, allow/deny, cidr, icmp_code, icmp_type,
          #                                             port from, port to
          [100, 'tcp', 'allow', '0.0.0.0/0', null, null, 22, 22],
          [200, 'tcp', 'allow', '0.0.0.0/0', null, null, 80, 80],
      ]
      egress: [
          [100, 'all', 'allow', '0.0.0.0/0', null, null, null, null]
      ]
      state: 'present'

# Same as above, but with rules in dict format
- name: "Create and associate production DMZ network ACL"
  ec2_vpc_nacl:
    vpc: 'prod'
    nacl: 'prod-dmz'
    region: 'us-east-1'
    subnets: ['prod-dmz-1', 'prod-dmz-2']
    ingress: [
      {'rule_number': 100,
       'protocol': 'tcp',
       'rule_action': 'allow',
       'cidr_block': '0.0.0.0/0',
       'icmp_code': null,
       'icmp_type': null,
       'port_range_from': 22,
       'port_range_to': 22},

      {'rule_number': 200,
       'protocol': 'tcp',
       'rule_action': 'allow',
       'cidr_block': '0.0.0.0/0',
       'icmp_code': null,
       'icmp_type': null,
       'port_range_from': 80,
       'port_range_to': 80},
    ]
    egress: [
      {'rule_number': 100,
       'protocol': 'all',
       'rule_action': 'allow',
       'cidr_block': '0.0.0.0/0',
       'icmp_code': null,
       'icmp_type': null,
       'port_range_from': null,
       'port_range_to': null},
    ]
    state: 'present'

# Same as above, but with unneeded fields removed (icmp_code, icmp_type)
- name: "Create and associate production DMZ network ACL"
  ec2_vpc_nacl:
    vpc: 'prod'
    nacl: 'prod-dmz'
    region: 'us-east-1'
    subnets: ['prod-dmz-1', 'prod-dmz-2']
    ingress: [
      {'rule_number': 100,
       'protocol': 'tcp',
       'rule_action': 'allow',
       'cidr_block': '0.0.0.0/0',
       'port_range_from': 22,
       'port_range_to': 22},

      {'rule_number': 200,
       'protocol': 'tcp',
       'rule_action': 'allow',
       'cidr_block': '0.0.0.0/0',
       'port_range_from': 80,
       'port_range_to': 80},
    ]
    egress: [
      {'rule_number': 100,
       'protocol': 'all',
       'rule_action': 'allow',
       'cidr_block': '0.0.0.0/0',
       'port_range_from': null,
       'port_range_to': null},
    ]
    state: 'present'

# Ensure the network ACL named 'legacy-dmz' has no subnets associated with it
- name: "Disassociate legacy-dmz"
  ec2_vpc_nacl:
    vpc: 'core'
    nacl: 'legacy-dmz'
    region: 'us-east-1'
    state: 'disassociated'

# Ensure that a network ACL with a wide-open ingress and egress rule is removed
- name: "Remove open network ACL"
  ec2_vpc_nacl:
      vpc: 'prod'
      region: 'us-east-1'
      ingress: [
          # rule no, protocol, allow/deny, cidr, icmp_code, icmp_type,
          #                                             port from, port to
          [100, 'all', 'allow', '0.0.0.0/0', null, null, null, null],
      ]
      egress: [
          [100, 'all', 'allow', '0.0.0.0/0', null, null, null, null]
      ]
      state: 'absent'

# Create a rule permitting TCP on all incoming ports on the test VPC
# (from port 0 to maximum port number)
- name: "Create NACL permitting TCP on all ports"
  ec2_vpc_nacl:
      vpc: 'test'
      region: 'us-east-1'
      ingress: [
          # rule no, protocol, allow/deny, cidr, icmp_code, icmp_type,
          #                                             port from, port to
          [100, 'tcp', 'allow', '0.0.0.0/0', null, null, 0, "max"],
      ]
      state: 'present'

'''


#  imports ####################################################################
from boto.exception import EC2ResponseError
from collections import defaultdict, namedtuple, Iterable, Mapping
from copy import copy
from functools import partial, total_ordering
from itertools import chain
from operator import attrgetter

import boto.vpc
import re


#  constants ##################################################################
# Fields for network ACL entries/rules
ACL_ENTRY_FIELDS = [
    'rule_number',
    'protocol',
    'rule_action',
    'egress',
    'cidr_block',
    'icmp_code',
    'icmp_type',
    'port_range_from',
    'port_range_to',
]

CIDR_RE = re.compile('^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$')
NACL_RE = re.compile('^acl-[A-z0-9]+$')

# Common fields for the default rule that is contained within every VPC NACL.
DEFAULT_RULE_FIELDS = {
    'rule_number': 32767,
    'rule_action': 'deny',
    'cidr_block':  '0.0.0.0/0',
}

DEFAULT_INGRESS = dict(DEFAULT_RULE_FIELDS.items() + [('egress', False)])
DEFAULT_EGRESS = dict(DEFAULT_RULE_FIELDS.items() + [('egress', True)])

# Maximum TCP/UDP port
MAX_PORT_NUM = 65535

# VPC-supported IANA protocol numbers
# http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
PROTOCOL_NUMBERS = {'all': -1, 'icmp': 1, 'tcp': 6, 'udp': 17, }
PROTOCOL_NAMES = {v: k for k, v in PROTOCOL_NUMBERS.items()}


#  ############################################################################
awsapi = None


#  defs #######################################################################
def find_one_aws_resource(
        resource_get_func, parameters_list, selector_func=None):
    '''
    Given a function to get AWS resources and a list of parameter dicts,
    calls the get function with each parameter dict until a single resource
    is found.

    If more than one resource is found and a 'selector_func' is specified,
    that function is called on the resultant group to see if a single resource
    can be isolated.

    If a single resource is found or isolated, return it.
    If no resources are found with every attempt, return None.
    Else we can't find a single resource, raise TooManyItems.
    '''
    results = list()

    for params in parameters_list:
        try:
            temp = resource_get_func(**params)
        except EC2ResponseError, e:
            if 'notfound' in e.error_code.lower():
                results.append([])
                continue
            else:
                raise

        size = len(temp)

        if size == 1:
            return temp[0]

        if (size > 1) and selector_func:
            select_temp = filter(selector_func, temp)
            if len(select_temp) == 1:
                return select_temp[0]

        results.append(temp)

    if sum(map(len, results)) == 0:
        return None
    else:
        raise TooManyItems()


def find_resource_by_identifier(
        identifier, resource_get_func, id_parameter_name,
        search_filters=[], common_filter={}, tags={},
        resource_type='resource',
        selector_func=None,
        supports_name_tag=True,
        too_many_msg=None):
    '''
    Given some sort of identifier for a resource, a function that can fetch
    resources and the name of the parameter used to specify resource IDs
    for the get function, use these to locate a single resource with that
    identifier.

    If 'supports_name_tag' is set to True, also attempts to find this resource
    using the identifier as a Name tag.

    Search filters to use to locate the resource can be specified by passing
    in a list of filter dicts via the 'search_filters' parameter.

    Tags to use to filter items can also be passed in via the 'tags' parameter.
    (As a dict)

    If there is a filter set that should be included in every search filter set
    in 'search_filters', it can be specified as a dict in 'common_filters'.

    Returns:
    * the resource if found.
    * None if it could not be located at all.

    Raises:
    * TooManyItems if there are too many matches and a single resource
      cannot be found.
    '''
    params_list = list()
    base_filters = copy(common_filter)

    if tags:
        tag_filters = tags_as_filters(tags)
        base_filters.update(tag_filters)

    for search_filter in search_filters:
        temp = copy(search_filter)
        temp.update(base_filters)
        params_list.append({'filters': temp})

    if identifier:
        params_list.append(
            {id_parameter_name: [identifier], 'filters': base_filters})

        if supports_name_tag:
                name_filter = {'tag:Name': identifier}
                name_filter.update(base_filters)
                params_list.append({'filters': name_filter})

    if not params_list:
        params_list.append({'filters': base_filters})

    if not too_many_msg:
        too_many_msg = ((
            'Too many {type}s found for "{id}". Try using more specific'
            ' criteria, such as the {type} ID or other distinct attributes.').
            format(type=resource_type, id=identifier))
    try:
        result = find_one_aws_resource(
            resource_get_func, params_list, selector_func=selector_func)
    except TooManyItems:
        raise ValueError(too_many_msg)
    return result


def get_aws_api(module):
    '''
    Get a common AWSAPI instance.
    '''
    global awsapi
    if not awsapi:
        aws_conn_info = (module.params.get('region'), None, {})
        aws_region = aws_conn_info[0]
        boto_params = aws_conn_info[2]
        awsapi = AWSAPI(aws_region, **boto_params)
    return awsapi


def is_cidr_format(strng):
    '''
    Returns True or False depending on whether the given string looks like
    a CIDR block specification.
    '''
    return bool(re.match(CIDR_RE, strng))


def resembles_nacl_id(strng):
    '''
    Return True if the given string looks like a NACL ID.
    '''
    return bool(re.match(NACL_RE, strng))


def is_integer(value):
    '''
    Returns True if the specified value is an integer.
    '''
    if isinstance(value, int):
        return True
    else:
        try:
            int(value)
        except (ValueError, TypeError):
            return False
        return True


def is_protocol(protocol):
    '''
    Given an integer or string, returns True or False depending on if:
    * the given integer is a valid protocol number
    * the given string is a valid protocol name
    '''
    if is_integer(protocol):
        return int(protocol) in PROTOCOL_NUMBERS.values()
    else:
        return protocol in PROTOCOL_NAMES.values()
    return False


def lookup_protocol(protocol, as_number=False):
    if not is_protocol(protocol):
        raise ValueError('Invalid/unknown protocol "{}"'.format(protocol))

    name, num = (None, None)

    if is_integer(protocol):
        p = int(protocol)
        name = PROTOCOL_NAMES[p]
        num = p
    else:
        name = protocol
        num = PROTOCOL_NUMBERS[protocol]

    return num if as_number else name


def tags_as_filters(tags):
    '''
    Given a dictionary or list of key value tuples representing a set of tags,
    return the tags as a dictionary in the format that can be used as search
    filters.
    '''
    if isinstance(tags, dict):
        items = tags.items()
    elif isinstance(tags, Iterable):
        items = tags
    else:
        raise TypeError('Unsupported data type for tags.')

    filters = {'tag:{}'.format(item[0]): item[1] for item in items}
    return filters


def nacl_to_dict(networkacl):
    '''
    Given a NetworkAcl object, return it as a dictionary.
    '''
    nacl_dict = dict()

    if not networkacl:
        return nacl_dict

    associations = map(lambda s: s.subnet_id, networkacl.associations)
    nacl_entries = map(str, RuleSet(networkacl).rules)

    if networkacl.tags and 'Name' in networkacl.tags:
        name = networkacl.tags['Name']
    else:
        name = ''

    nacl_dict.update({
        'id': networkacl.id,
        'name': name,
        'vpc_id': networkacl.vpc_id,
        'network_acl_entries': nacl_entries,
        'associations': associations,
        'tags': networkacl.tags,
    })
    return nacl_dict


#  classes ####################################################################
class ActionResults(object):
    '''
    Module action state and results convenience class
    '''
    def __init__(self):
        self.changed = False
        self.nacl = None
        self.added_rules = list()
        self.removed_rules = list()
        self.added_subnets = list()
        self.removed_subnets = list()
        self.nacl_list = list()

    def as_dict(self):
        if self.nacl_list:
            return {'results': self.nacl_list}
        else:
            return {
                'changed': self.changed,
                'nacl': nacl_to_dict(self.nacl),
                'added_rules': map(unicode, self.added_rules),
                'removed_rules': map(unicode, self.removed_rules),
                'added_subnets': list(set(self.added_subnets)),
                'removed_subnets': list(set(self.removed_subnets))
            }


class AWSAPI(object):
    '''
    Utility class for calling against the AWS API
    '''
    def __init__(self, region, **boto_params):
        self.conn = boto.vpc.connect_to_region(region, **boto_params)
        if not self.conn:
            raise LocalModuleException(
                'Failed to initialize connection to AWS. '
                'Double-check AWS region and boto configuration.')

    def associate_subnet(self, networkacl_id, subnet_id):
        '''
        Given a network ACL ID and a subnet ID, associate the subnet with
        the network ACL.
        '''
        return self.conn.associate_network_acl(networkacl_id, subnet_id)

    def create_network_acl_entry(self, networkacl_id, **rule_fields):
        '''
        Given a network ACL ID, add the specified parameters to add a new rule.
        '''
        return self.conn.create_network_acl_entry(networkacl_id, **rule_fields)

    def create_nacl_from_ruleset(self, vpc_id, ruleset):
        '''
        Given a VPC ID and a RuleSet object, create a network ACL object
        within that VPC with ACL entries as specified by the ruleset.

        Returns the created NetworkAcl object.
        '''
        networkacl = self.conn.create_network_acl(vpc_id)
        for entry in ruleset:

            rule_params = entry.as_dict()

            addrule = self.conn.create_network_acl_entry(
                networkacl.id, **rule_params)

            if not addrule:
                raise LocalModuleException((
                    'Failure while trying to add rule "{}" to network ACL '
                    '"{}"').format(repr(rule_params), networkacl.id))
        return networkacl

    def delete_nacl(self, networkacl_id):
        '''
        Given a network ACL ID, delete it.
        '''
        return self.conn.delete_network_acl(networkacl_id)

    def delete_networkacl_entry(self, networkacl_id, rule_number, egress=None):
        return self.conn.delete_network_acl_entry(
            networkacl_id, rule_number, egress=egress)

    def disassociate_subnet(self, subnet_id, vpc_id=None):
        return self.conn.disassociate_network_acl(subnet_id, vpc_id=vpc_id)

    def find_nacl_matching_ruleset(self, vpc_id, target_ruleset):
        '''
        Given a VPC ID, and a RuleSet object, search network ACLs within that
        VPC and return the one whose ACL entries match the given RuleSet
        exactly.
        '''
        nacls = self.get_nacls(vpc_id)

        for networkacl in nacls:
            nacl_ruleset = RuleSet(networkacl)

            if nacl_ruleset == target_ruleset:
                return networkacl
        return None

    def find_nacl(
            self, identifier, vpc=None, default=False, filters={}, tags={}):
        '''
        Given a network ACL identifier, which could be a tagged name, CIDR
        block or actual ACL ID, find and return the matching NetworkAcl object.

        If 'default' is set to True, will search for network ACLs that are
        the default ACLs for their VPC.

        Returns None if nothing found.
        '''
        nacl_get_func = self.conn.get_all_network_acls
        nacl_id_param = 'network_acl_ids'

        common_filter = dict()
        resource_type = 'network ACL'
        search_filters = list()

        if default:
            common_filter['default'] = 'true'

        if vpc:
            found_vpc = self.find_vpc(vpc)
            if not found_vpc:
                raise ValueError('Could not find VPC "{}" for subnet "{}"'
                                 .format(vpc, identifier))
            selector_func = partial(self.is_in_vpc, found_vpc.id)
        else:
            selector_func = None

        too_many_msg = (
            'Too many network ACLs found for "{id}".  Try using the network '
            'ACL ID, CIDR or additionally specifying the VPC name or ID of '
            'the particular network ACL you want.'.format(id=identifier))

        return find_resource_by_identifier(
            identifier, nacl_get_func, nacl_id_param,
            search_filters=search_filters,
            common_filter=common_filter,
            resource_type=resource_type,
            selector_func=selector_func,
            tags=tags,
            too_many_msg=too_many_msg)

    def find_vpc(self, identifier, tags={}):
        '''
        Given a VPC identifier which could be a tagged name, VPC CIDR or
        VPC ID, find and return the matching VPC object.

        Returns None if nothing found.
        '''
        vpc_get_func = self.conn.get_all_vpcs
        vpc_id_param = 'vpc_ids'

        common_filter = {'state': 'available'}
        resource_type = 'VPC'
        search_filters = list()

        if identifier and is_cidr_format(identifier):
            search_filters.append({'cidr': identifier})

        return find_resource_by_identifier(
            identifier, vpc_get_func, vpc_id_param,
            search_filters=search_filters,
            common_filter=common_filter,
            resource_type=resource_type,
            tags=tags)

    def find_subnet(self, identifier, vpc=None):
        '''
        Given a subnet identifier that could be a tagged name, CIDR block
        or subnet ID, find and return the matching subnet object.

        Returns None if nothing found.
        '''
        subnet_get_func = self.conn.get_all_subnets
        subnet_id_param = 'subnet_ids'

        common_filter = {'state': 'available'}
        resource_type = 'subnet'
        search_filters = list()

        if identifier and is_cidr_format(identifier):
            search_filters.append({'cidrBlock': identifier})

        if vpc:
            if isinstance(vpc, basestring):
                found_vpc = self.find_vpc(vpc)
                if not found_vpc:
                    raise ValueError('Could not find VPC "{}" for subnet "{}"'
                                     .format(vpc, identifier))
            elif isinstance(vpc, boto.vpc.VPC):
                found_vpc = vpc
            else:
                raise TypeError('Given VPC paramater is an unsupported type.')
            selector_func = partial(self.is_in_vpc, found_vpc.id)
        else:
            selector_func = None

        return find_resource_by_identifier(
            identifier, subnet_get_func, subnet_id_param,
            search_filters=search_filters,
            common_filter=common_filter,
            resource_type=resource_type,
            selector_func=selector_func)

    def get_default_nacl_for_vpc_id(self, vpc_id):
        '''
        Given a VPC, return its default network ACL.
        '''
        nacls = self.conn.get_all_network_acls(filters={'default': 'true',
                                                        'vpc-id': vpc_id})
        if not nacls:
            return None
        return nacls[0]

    def get_nacl_by_id(self, networkacl_id):
        nacls = self.conn.get_all_network_acls(network_acl_ids=[networkacl_id])
        return nacls[0]

    def get_nacls(self, vpc_identifier=None):
        '''
        Gets the list of all network ACLs.

        If a VPC identifer is specified, be it name, CIDR or VPC ID, gets only
        the list of network ACLs in that VPC.
        '''
        if not vpc_identifier:
            return self.conn.get_all_network_acls()
        vpc = self.find_vpc(vpc_identifier)
        if not vpc:
            raise ValueError(
                'No VPC found with identifier "{}"'.format(vpc_identifier))
        return self.conn.get_all_network_acls(
            filters={'vpc-id': vpc.id})

    def get_associated_subnet_ids_for_nacl_id(self, networkacl_id):
        '''
        Returns a list of associated subnet IDs for a given network ACL ID.
        '''
        nacl = self.get_nacl_by_id(networkacl_id)
        get_subnet_id = attrgetter('subnet_id')
        return list(frozenset(map(get_subnet_id, nacl.associations)))

    def get_subnet_association_map(self, vpc_identifier=None):
        '''
        Return a dictionary mapping all subnets to a list of their association
        IDs.
        '''
        subnet_map = defaultdict(set)

        all_nacls = self.get_nacls(vpc_identifier)

        get_assoc = attrgetter('associations')
        add_assoc_id = lambda a: subnet_map[a.subnet_id].add(a.id)
        associations = chain(*filter(None, map(get_assoc, all_nacls)))
        map(add_assoc_id, associations)

        return {k: list(v) for k, v in subnet_map.items()}

    @classmethod
    def is_in_vpc(cls, vpc_id, vpc_contained_thing):
        return vpc_contained_thing.vpc_id == vpc_id


@total_ordering
class RuleSet(object):
    '''
    A RuleSet is a collection of network ACL entries.
    '''
    def __init__(self, rules):
        self.rules = set()
        if isinstance(rules, boto.vpc.networkacl.NetworkAcl):
            rules_set = self._rules_set_from_networkacl(rules)
        elif isinstance(rules, Iterable):
            rules_set = self._rules_set_from_iterable(rules)
        else:
            raise TypeError('Unsupported rules type: "{}"'.format(type(rules)))
        self.rules.update(rules_set)
        self.discard_defaults()

    def discard_defaults(self):
        self.rules.discard(NaclEntry.from_dict(DEFAULT_EGRESS))
        self.rules.discard(NaclEntry.from_dict(DEFAULT_INGRESS))

    @classmethod
    def item_to_naclentry(cls, item, egress=None):
        '''
        Take any given item and return it as a NaclEntry.

        Raise a TypeError whenever we run into an item type we don't support.
        '''
        if isinstance(item, NaclEntry):
            entry = item
        if isinstance(item, Mapping):
            entry = NaclEntry.from_dict(item)
        elif isinstance(item, Iterable):
            entry = NaclEntry.from_list(item)
        else:
            raise TypeError('Unsupported rule type: "{}"'.format(type(item)))
        entry.validate()
        return entry

    def is_ruleset(self, item):
        return isinstance(item, type(self))

    def difference(self, item):
        '''
        Set difference against this RuleSet's rules.
        '''
        if self.is_ruleset(item):
            return self.rules.difference(item.rules)
        else:
            return self.rules.difference(item)

    def update(self, item):
        self.rules.update(item)

    @classmethod
    def _rules_set_from_iterable(cls, iterable):
        '''
        Given a list or other iterable containing rule/ACL entries,
        return a set of NaclEntry objects.
        '''
        rules = list()
        for item in iterable:
            rules.append(cls.item_to_naclentry(item))
        return set(rules)

    @classmethod
    def _rules_set_from_networkacl(cls, networkacl):
        '''
        Given a network ACL object, return an instance of Ruleset
        representing that ACL object's entries.
        '''
        return set(map(NaclEntry.from_networkacl_entry,
                       networkacl.network_acl_entries))

    def __eq__(self, other):
        if self.is_ruleset(other):
            return self.rules == other.rules
        elif isinstance(other, Iterable):
            return self.rules == set(other)
        else:
            raise NotImplemented()

    def __lt__(self, other):
        if self.is_ruleset(other) or isinstance(other, Iterable):
            return self.rules < other
        else:
            raise NotImplemented()

    def __contains__(self, name):
        return name in self.rules

    def __len__(self):
        return len(self.rules)

    def __hash__(self):
        return hash(frozenset(self.rules))

    def __iter__(self):
        return iter(self.rules)


class NaclEntry(namedtuple('NaclEntry', ACL_ENTRY_FIELDS)):
    '''
    Represents a network ACL rule entry.
    '''
    def __new__(cls, **params):
        fields = defaultdict(None, **params)
        map(fields.setdefault, ACL_ENTRY_FIELDS)

        if fields['protocol'] is None:
            fields['protocol'] = -1

        if isinstance(fields['protocol'], basestring):
            proto = fields['protocol']
            fields['protocol'] = \
                unicode(lookup_protocol(proto, as_number=True))

        if isinstance(fields['rule_action'], basestring):
            fields['rule_action'] = fields['rule_action'].lower()

        if isinstance(fields['port_range_to'], basestring):
            to_port = fields['port_range_to']
            if to_port.lower() == 'max':
                fields['port_range_to'] = MAX_PORT_NUM

        if isinstance(fields['port_range_from'], basestring):
            from_port = fields['port_range_from']
            if from_port.lower() == 'max':
                fields['port_range_from'] = MAX_PORT_NUM

        for field in fields:
            if isinstance(fields[field], int):
                fields[field] = unicode(fields[field])

            if isinstance(fields[field], bool):
                fields[field] = unicode(repr(fields[field]).lower())

            if isinstance(fields[field], basestring):
                fields[field] = fields[field].lower()

        return super(NaclEntry, cls).__new__(cls, **fields)

    def as_dict(self):
        return {field: getattr(self, field) for field in self._fields}

    def __str__(self):
        return str(self.as_dict())

    def validate(self):
        '''
        Validates this ACL entry and raises exceptions for any invalid
        conditions encountered.
        '''
        if not is_protocol(self.protocol):
            raise ValueError('Unsupported protocol: {}'.format(self.protocol))

        if not self.egress or self.egress not in ('true', 'false'):
            raise ValueError(
                'Rule egress (rule_egress) must be either "true" or "false"')

        if not self.rule_number:
            raise ValueError('Rule number (rule_number) MUST be set.')

        if not is_integer(self.rule_number):
            raise TypeError('Rule number (rule_number) must be an integer.')

        if not self.cidr_block:
            raise ValueError('CIDR block must be specified.')

        if not self.rule_action or (
                self.rule_action.lower() not in ('allow', 'deny')):
            raise ValueError(
                'The rule action (rule_action) must be defined, and must be '
                'one of "allow" or "deny"')

        if lookup_protocol(self.protocol).lower() in ('tcp', 'udp'):
            if not self.port_range_from or not self.port_range_to:
                raise ValueError(
                    'Starting and ending port range '
                    '(port_range_from, port_range_to) MUST be specified if '
                    'protocol is UDP or TCP')

            if not is_integer(self.port_range_from) or \
                    not is_integer(self.port_range_to):
                raise TypeError('port_range_from and port_range_to must be '
                                'integers.')

        if lookup_protocol(self.protocol).lower() == 'icmp':
            if not self.icmp_code or not self.icmp_type:
                raise ValueError(
                    'ICMP type and code (icmp_code, icmp_type) MUST be '
                    'specified if protocol is ICMP.')

            if not is_integer(self.icmp_code) or \
                    not is_integer(self.icmp_type):
                raise TypeError('icmp_code and icmp_type must be integers.')

    @classmethod
    def from_dict(cls, entry_dict):
        params = {field: entry_dict[field] for field in
                  ACL_ENTRY_FIELDS if field in entry_dict}
        return cls(**params)

    @classmethod
    def from_list(cls, args_list):
        tmp = zip(ACL_ENTRY_FIELDS, args_list)
        return cls(**dict(tmp))

    @classmethod
    def from_networkacl_entry(cls, network_acl_entry):
        port_range_from, port_range_to = (None, None)
        icmp_code, icmp_type = (None, None)

        if network_acl_entry.port_range:
            port_range_from = network_acl_entry.port_range.from_port
            port_range_to = network_acl_entry.port_range.to_port

        if network_acl_entry.icmp:
            icmp_code = network_acl_entry.icmp.code
            icmp_type = network_acl_entry.icmp.type

        return cls(
            rule_number=network_acl_entry.rule_number,
            protocol=network_acl_entry.protocol,
            rule_action=network_acl_entry.rule_action,
            egress=network_acl_entry.egress,
            cidr_block=network_acl_entry.cidr_block,
            port_range_from=port_range_from,
            port_range_to=port_range_to,
            icmp_code=icmp_code,
            icmp_type=icmp_type)


class NetworkACLModule(object):
    '''
    Ansible module main class for managing VPC network ACLs
    '''
    STATES = {
        'PRESENT': ('present',),
        'REMOVED': ('absent',),
        'ASSOCIATE': ('associated', 'associate'),
        'DISASSOCIATE': ('disassociated', 'disassociate'),
        'LIST': ('list',),
    }

    def __init__(self, module):
        self.aws = get_aws_api(module)
        self.module = module

        self.nacl_identifier = module.params.get('nacl')
        self.vpc_identifier = module.params.get('vpc')
        self.subnets = module.params.get('subnets')
        self.tags = module.params.get('tags', dict())
        self.state = module.params.get('state')

        self.init_and_validate_params()

    def init_and_validate_params(self):
        '''
        Initialize and validate given fields as per module configuration.
        Raises ValueError for conditions failining validation.
        '''
        if self.vpc_identifier:
            self.vpc = self.aws.find_vpc(self.vpc_identifier)
            if not self.vpc:
                raise ValueError('Could not find VPC "{}"'
                                 .format(self.vpc_identifier))
        else:
            self.vpc = None

        self.ruleset = self.get_ruleset()
        self.want_default_nacl = self.module.params.get('use_default_nacl')

    def describe_nacl_identifiers(self):
        '''
        Return a plain English description of all the configured module
        parameters that are used to identify a network ACL.
        '''
        description = list()
        if self.want_default_nacl and self.vpc_identifier:
            description.append('default network ACL for VPC "{}"'
                               .format(self.vpc_idenfier))
        elif self.nacl_identifier and self.vpc_identifier:
            description.append('network ACL "{n}" in VPC "{v}"'
                               .format(n=self.nacl_identifier,
                                       v=self.vpc_identifier))
        elif self.nacl_identifier:
            description.append('network ACL "{}"'.
                               format(self.nacl_identifier))
        if self.tags:
            description.append('with tags "{}"'.format(repr(self.tags)))

        if not description:
            description.append(
                'anything - no identifier that could be used to identify'
                ' a network ACL has been specified.')
        return ' '.join(description)

    def find_identified_nacl(self, fail_on_not_found=True):
        '''
        Find and return a network ACL matching identifiers as specified
        in module parameters.
        '''
        target_nacl = None

        if self.want_default_nacl:
            if self.vpc_identifier:
                target_nacl = self.aws.get_default_nacl_for_vpc_id(self.vpc.id)
            else:
                raise ValueError(
                    'A valid VPC identifier is required if the default NACL'
                    ' is desired.')
        elif self.nacl_identifier or self.tags:

            target_nacl = self.aws.find_nacl(self.nacl_identifier,
                                             vpc=self.vpc_identifier,
                                             default=self.want_default_nacl,
                                             tags=self.tags)

        if not target_nacl and fail_on_not_found:
            raise ValueError('Could not find {}'.format(
                self.describe_nacl_identifiers()))

        return target_nacl

    def get_action_sequence(self):
        '''
        Return the list of actions that should be run as per module parameters.
        '''
        actions = list()

        find_possible_nacl = partial(self.find_nacl_action,
                                     fail_on_not_found=False)

        if self.state in self.STATES['PRESENT']:

            if self.nacl_identifier and not self.ruleset_present:
                actions = [self.find_nacl_action]
            else:
                actions = [find_possible_nacl,
                           self.create_nacl_action]

            actions = actions + \
                [self.modify_nacl_action,
                 self.modify_nacl_to_ruleset_action,
                 self.associate_subnets_action,
                 self.refresh_nacl_action]

        elif self.state in self.STATES['REMOVED']:

            actions = [find_possible_nacl,
                       self.disassociate_subnets_action,
                       self.destroy_nacl_action]

        elif self.state in self.STATES['ASSOCIATE']:

            actions = [self.find_nacl_action,
                       self.associate_subnets_action,
                       self.refresh_nacl_action]

        elif self.state in self.STATES['DISASSOCIATE']:

            actions = [find_possible_nacl,
                       self.disassociate_subnets_action,
                       self.refresh_nacl_action]

        elif self.state in self.STATES['LIST']:

            actions = [self.list_nacls_action]

        else:
            raise LocalModuleException('Unrecognized desired state.')

        return actions

    def get_ruleset(self):
        '''
        Returns a RuleSet from the configured egress and ingress module
        parameters.
        '''
        ingress_rules = self.module.params.get('ingress')
        egress_rules = self.module.params.get('egress')
        egress_field_index = ACL_ENTRY_FIELDS.index('egress')
        purge_rules = self.module.params.get('purge_rules')

        self.ruleset_present = False

        if not purge_rules and not egress_rules and not ingress_rules:
            return None

        rules = list()

        def insert_egress_param(item, egress_state):
            if isinstance(item, Mapping):
                item['egress'] = egress_state
            elif isinstance(item, Iterable):
                item.insert(egress_field_index, egress_state)
            else:
                raise ValueError('Unknown rule format: "{}"'.format(item))
            return item

        rules.extend(
            map(lambda i: insert_egress_param(i, False), ingress_rules))

        rules.extend(
            map(lambda i: insert_egress_param(i, True), egress_rules))

        self.ruleset_present = True
        return RuleSet(rules)

    def get_subnet_ids(self, subnet_identifiers):
        '''
        Given a list of subnet identifiers that could be in the format of a
        CIDR, tagged name or subnet ID, return a list of the subnet IDs.

        Raise ValueError for any subnets that can't be located.
        '''
        subnet_ids = list()

        for subnet_identifier in self.subnets:
            subnet = self.aws.find_subnet(subnet_identifier, vpc=self.vpc)

            if not subnet:
                vpc_desc = \
                    ' in VPC "{}"'.format(self.vpc.id) if self.vpc else ''
                raise ValueError('Could not find subnet "{}"{}'
                                 .format(subnet_identifier, vpc_desc))
            subnet_ids.append(subnet.id)
        return subnet_ids

    #
    #  Actions - take and return an ActionResults instance, modifying 'changed'
    #            and data as changes are made in a "pipeline" workflow
    #
    def destroy_nacl_action(self, actionresult):
        '''
        Delete the current network ACL if found.
        '''
        if not actionresult.nacl:
            return actionresult

        try:
            self.aws.delete_nacl(actionresult.nacl.id)
            actionresult.changed = True
        except EC2ResponseError, e:
            if 'invalidnetworkaclid' in e.message.lower():
                pass
            else:
                raise
        return actionresult

    def find_nacl_action(self, actionresult, fail_on_not_found=True):
        '''
        Find the NACL as described by the given identifier.

        If fail_on_not_found is set to True, raises an Exception if
        none could be located as per given module parameters.
        '''
        target_nacl = self.find_identified_nacl(
            fail_on_not_found=fail_on_not_found)

        if not target_nacl and self.ruleset:
            if not self.vpc:
                raise ValueError(
                    'VPC not found or set.  No NACL identifier has been set, '
                    'so searching by ruleset, which requires a valid VPC '
                    'identifier.')

            # If we're here, then no explicit network ACL was specified,
            # but we have been given a ruleset.  So we should go look for
            # a network ACL that matches the ruleset we've been given.
            target_nacl = \
                self.aws.find_nacl_matching_ruleset(self.vpc.id, self.ruleset)

        if not target_nacl and fail_on_not_found:
            raise ValueError((
                'Could not find {}. Specify or revise NACL ID, VPC or tags.'
                ' Or specify a ruleset to find and use a network ACL with '
                'those rules.').format(self.describe_nacl_identifiers()))

        actionresult.nacl = target_nacl
        return actionresult

    def create_nacl_action(self, actionresult):
        '''
        Create a NACL if none currently present.
        '''

        if not actionresult.nacl:
            if not self.ruleset_present:
                raise ValueError(
                    'Egress/ingress ruleset required when creating network '
                    'ACL.')

            actionresult.nacl = \
                self.aws.create_nacl_from_ruleset(self.vpc.id, self.ruleset)

            if actionresult.nacl:
                actionresult.changed = True

        if not actionresult.nacl:
            # If we're at this point and we don't have a network ACL object,
            # something went very wrong.
            raise LocalModuleException(
                'No network ACL module located or created.')

        return actionresult

    def refresh_nacl_action(self, actionresult):
        '''
        Get the latest state of the current network ACL from AWS.
        '''
        if not actionresult.nacl:
            return actionresult

        actionresult.nacl = self.aws.get_nacl_by_id(actionresult.nacl.id)
        return actionresult

    def associate_subnets_action(self, actionresult):
        '''
        Associate any listed subnets to the NACL
        '''
        if not actionresult.nacl and not self.subnets:
            raise ValueError(
                'A NACL identifier (NACL ID/CIDR/Name) and a list subnets is '
                'required if associating subnets.')

        nacl = actionresult.nacl

        current_associations = self.aws.get_subnet_association_map()
        subnet_ids = self.get_subnet_ids(self.subnets)

        for subnet_id in subnet_ids:
            assoc_id = self.aws.associate_subnet(nacl.id, subnet_id)

            if assoc_id not in current_associations[subnet_id]:
                actionresult.added_subnets.append(subnet_id)
                actionresult.changed = True

        return actionresult

    def disassociate_subnets_action(self, actionresult):
        '''
        Disssociate any listed subnets to the NACL
        '''
        subnet_ids = list()

        if actionresult.nacl:
            subnet_ids.extend(
                self.aws.get_associated_subnet_ids_for_nacl_id(
                    actionresult.nacl.id))

        if self.subnets:
            subnet_ids.extend(self.get_subnet_ids(self.subnets))

        params = {'vpc_id': self.vpc.id} if self.vpc else dict()
        current_associations = self.aws.get_subnet_association_map()

        for subnet_id in subnet_ids:
            assoc_id = self.aws.disassociate_subnet(subnet_id, **params)

            if assoc_id not in current_associations[subnet_id]:
                actionresult.removed_subnets.append(subnet_id)
                actionresult.changed = True

        return actionresult

    def list_nacls_action(self, actionresult):
        '''
        Simply list all network ACLs.
        '''
        nacls = self.aws.get_nacls(vpc_identifier=self.vpc_identifier)
        actionresult.nacl_list = map(nacl_to_dict, nacls)
        return actionresult

    def modify_nacl_action(self, actionresult):
        '''
        Make changes to NACL attributes (such as tags) if necessary.
        '''
        if not actionresult.nacl:
            return actionresult

        target_nacl = actionresult.nacl
        tags = self.tags or dict()

        # If the given NACL identifier does not look like a CIDR
        # or network ACL ID, then it's a name, and if the name tag
        # is not already specified, then set this as the name.
        if self.nacl_identifier and \
                not is_cidr_format(self.nacl_identifier) and \
                not resembles_nacl_id(self.nacl_identifier) and \
                'Name' not in tags:
            tags.update({'Name':  self.nacl_identifier})

        if target_nacl and tags:
            if target_nacl.tags != tags:
                target_nacl.add_tags(tags)
                actionresult.changed = True

        return actionresult

    def modify_nacl_to_ruleset_action(self, actionresult):
        '''
        Modify the current network ACL to match the current ruleset.
        '''
        if not actionresult.nacl:
            return actionresult

        if not self.ruleset_present:
            return actionresult

        current_ruleset = RuleSet(actionresult.nacl)
        target_ruleset = RuleSet(self.ruleset)

        to_be_created = target_ruleset.difference(current_ruleset)
        to_be_removed = current_ruleset.difference(target_ruleset)

        is_egress = lambda r: unicode(r.egress).lower() == 'true'

        for rule in to_be_removed:
            self.aws.delete_networkacl_entry(
                actionresult.nacl.id, rule.rule_number, is_egress(rule))
            actionresult.removed_rules.append(rule)
            actionresult.changed = True

        for rule in to_be_created:
            self.aws.create_network_acl_entry(
                actionresult.nacl.id, **rule.as_dict())
            actionresult.added_rules.append(rule)
            actionresult.changed = True

        return actionresult


#  exceptions #################################################################
class LocalModuleException(Exception):
    pass


class TooManyItems(LocalModuleException):
    pass


#  main #######################################################################
def get_ansible_module():
    valid_states = list(chain(*NetworkACLModule.STATES.values()))

    argument_spec = ec2_argument_spec()

    argument_spec.update(dict(
        egress=dict(
            required=False, type='list', default=list(),
            aliases=['rules_egress']),
        ingress=dict(
            required=False, type='list', default=list(),
            aliases=['rules']),
        nacl=dict(required=False, aliases=['name']),
        purge_rules=dict(required=False, type='bool', default=False),
        state=dict(default='present', choices=valid_states),
        subnets=dict(required=False, type='list', default=list()),
        tags=dict(required=False, type='dict', aliases=['resource_tags']),
        use_default_nacl=dict(required=False, type='bool', default=False),
        vpc=dict(required=False, aliases=['vpc_id']),
        ),
    )

    return AnsibleModule(argument_spec=argument_spec,
                         mutually_exclusive=[['nacl', 'use_default_nacl']])


def main():

    module = get_ansible_module()
    results = ActionResults()

    try:
        networkacl_mod = NetworkACLModule(module)
    except (LocalModuleException, EC2ResponseError, ValueError), e:
            module.fail_json(msg=e.message)

    action_list = networkacl_mod.get_action_sequence()

    for action in action_list:
        try:
            results = action(results)
        except (LocalModuleException, EC2ResponseError, ValueError), e:
            module.fail_json(msg=e.message)

    module.exit_json(**results.as_dict())


# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()
