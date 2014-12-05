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

DOCUMENTATION = '''
---
module: ec2_vpc
short_description: configure AWS virtual private clouds
description:
    - Create or terminates AWS virtual private clouds.  This module has a'''
''' dependency on python-boto.
version_added: "1.4"
options:
  cidr_block:
    description:
      - "The cidr block representing the VPC, e.g. 10.0.0.0/16"
    required: false, unless state=present
  instance_tenancy:
    description:
      - "The supported tenancy options for instances launched into the VPC."
    required: false
    default: "default"
    choices: [ "default", "dedicated" ]
  dns_support:
    description:
      - toggles the "Enable DNS resolution" flag
    required: false
    default: "yes"
    choices: [ "yes", "no" ]
  dns_hostnames:
    description:
      - toggles the "Enable DNS hostname support for instances" flag
    required: false
    default: "yes"
    choices: [ "yes", "no" ]
  subnets:
    description:
      - 'A list of subnet IDs, Name tags, or CIDRs to keep on the VPC. If'''
''' this argument is supplied, only those subnets listed will be kept;'''
''' others will be removed.'
    required: false
    default: null
    aliases: []
  vpc_id:
    description:
      - A VPC id to terminate when state=absent or to update
    required: false
    default: null
    aliases: []
  vpc_name:
    description:
      - Match or create VPC by this tag 'Name' value, rather than by vpc_id.'''
''' If vpc_id is supplied, the VPC's tag name will be updated to match.
    required: false
    default: null
    aliases: []
  resource_tags:
    description:
      - 'A dictionary array of resource tags of the form: { tag1: value1,'''
''' tag2: value2 }. Tags in this list are used in conjunction with CIDR'''
''' block to uniquely identify a VPC in lieu of vpc_id. Therefore, if'''
''' CIDR/Tag combination does not exits, a new VPC will be created.  VPC'''
''' tags not on this list will be ignored. Prior to 1.7, specifying a'''
''' resource tag was optional.'
    required: true
    default: null
    aliases: []
    version_added: "1.6"
  route_tables:
    description:
      - 'A list of route table IDs or Name tags to keep on the VPC. If this'''
''' argument is supplied, only those tables listed will be kept; others will'''
''' be removed.'
    required: false
    default: null
    aliases: []
  wait:
    description:
      - wait for the VPC to be in state 'available' before returning
    required: false
    default: "no"
    choices: [ "yes", "no" ]
    aliases: []
  wait_timeout:
    description:
      - how long before wait gives up, in seconds
    default: 300
    aliases: []
  state:
    description:
      - Create or terminate the VPC
    required: true
    default: present
    aliases: []
  region:
    description:
      - region in which the resource exists.
    required: false
    default: null
    aliases: ['aws_region', 'ec2_region']
  aws_secret_key:
    description:
      - AWS secret key. If not set then the value of the AWS_SECRET_KEY'''
''' environment variable is used.
    required: false
    default: None
    aliases: ['ec2_secret_key', 'secret_key' ]
  aws_access_key:
    description:
      - AWS access key. If not set then the value of the AWS_ACCESS_KEY'''
''' environment variable is used.
    required: false
    default: None
    aliases: ['ec2_access_key', 'access_key' ]
  validate_certs:
    description:
      - When set to "no", SSL certificates will not be validated for boto'''
''' versions >= 2.6.0.
    required: false
    default: "yes"
    choices: ["yes", "no"]
    aliases: []
    version_added: "1.5"

requirements: [ "boto" ]
author: Carson Gee
'''

EXAMPLES = '''
# Note: None of these examples set aws_access_key, aws_secret_key, or region.
# It is assumed that their matching environment variables are set.

# Basic creation example:
      ec2_vpc:
        state: present
        cidr_block: 172.23.0.0/16
        resource_tags: { "Environment":"Development" }
        region: us-west-2
      register vpc

# The absence or presence of subnets and route tables deletes or creates them
# respectively.
      local_action:
        module: ec2_vpc
        vpc_id: {{vpc.vpc_id}}
        subnets:
          - {{private_subnet.subnet_id}}
          - 'Database Subnet'
          - '10.0.0.0/8'
        route_tables:
          - {{public_route_table.route_table_id}}
          - 'NAT Route Table'

# Removal of a VPC by id
      ec2_vpc:
        state: absent
        vpc_id: vpc-aaaaaaa
        region: us-west-2
If you have added elements not managed by this module, e.g. instances, NATs,
etc. then the delete will fail until those dependencies are removed.
'''


import sys  # noqa
import time
import re

try:
    import boto.ec2
    import boto.vpc
    from boto.exception import EC2ResponseError
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False
    if __name__ != '__main__':
        raise


def vpc_json(vpc):
    """
    Serializes the boto VPC object into a dictionary suitable for use as an
    Ansible JSON result.
    """
    return({
        'id': vpc.id,
        'cidr_block': vpc.cidr_block,
        'dhcp_options_id': vpc.dhcp_options_id,
        'region': vpc.region.name,
        'state': vpc.state,
    })


def subnet_json(vpc_conn, subnet):
    """
    Serializes the boto subnet object into a dictionary suitable for use as an
    Ansible JSON result.
    """
    return {
        'resource_tags': dict(((t.name, t.value)
                               for t in vpc_conn.get_all_tags(
                                   filters={'resource-id': subnet.id}))),
        'cidr': subnet.cidr_block,
        'az': subnet.availability_zone,
        'id': subnet.id,
    }


class AnsibleVPCException(Exception):
    pass


class AnsibleSubnetSearchException(AnsibleVPCException):
    pass


CIDR_RE = re.compile('^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$')
SUBNET_RE = re.compile('^subnet-[A-z0-9]+$')
ROUTE_TABLE_RE = re.compile('^rtb-[A-z0-9]+$')


def find_subnets(vpc_conn, vpc_id, identified_subnets):
    """
    Finds a list of subnets, each identified either by a raw ID, a unique
    'Name' tag, or a CIDR such as 10.0.0.0/8.

    Note that this function is duplicated in other ec2 modules, and should
    potentially be moved into potentially be moved into a shared module_utils
    """
    subnet_ids = []
    subnet_names = []
    subnet_cidrs = []
    for subnet in (identified_subnets or []):
        if re.match(SUBNET_RE, subnet):
            subnet_ids.append(subnet)
        elif re.match(CIDR_RE, subnet):
            subnet_cidrs.append(subnet)
        else:
            subnet_names.append(subnet)

    subnets_by_id = []
    if subnet_ids:
        subnets_by_id = vpc_conn.get_all_subnets(
            subnet_ids, filters={'vpc_id': vpc_id})

        for subnet_id in subnet_ids:
            if not any(s.id == subnet_id for s in subnets_by_id):
                raise AnsibleVPCException('Subnet ID "{0}" does not exist'
                                          .format(subnet_id))

    subnets_by_cidr = []
    if subnet_cidrs:
        subnets_by_cidr = vpc_conn.get_all_subnets(
            filters={'vpc_id': vpc_id, 'cidr': subnet_cidrs})

        for cidr in subnet_cidrs:
            if not any(s.cidr_block == cidr for s in subnets_by_cidr):
                raise AnsibleVPCException('Subnet CIDR "{0}" does not exist'
                                          .format(subnet_cidr))

    subnets_by_name = []
    if subnet_names:
        subnets_by_name = vpc_conn.get_all_subnets(
            filters={'vpc_id': vpc_id, 'tag:Name': subnet_names})

        for name in subnet_names:
            matching = [s.tags.get('Name') == name for s in subnets_by_name]
            if len(matching) == 0:
                raise AnsibleVPCException('Subnet named "{0}" does not exist'
                                          .format(name))
            elif len(matching) > 1:
                raise AnsibleVPCException('Multiple subnets named "{0}"'
                                          .format(name))

    return subnets_by_id + subnets_by_cidr + subnets_by_name


def find_route_tables(vpc_conn, vpc_id, identified_route_tables):
    rt_ids = []
    rt_names = []
    for rt in (identified_route_tables or []):
        if re.match(ROUTE_TABLE_RE, rt):
            rt_ids.append(rt)
        else:
            rt_names.append(rt)

    route_tables_by_id = []
    if rt_ids:
        route_tables_by_id = vpc_conn.get_all_route_tables(
            rt_ids, filters={'vpc_id': vpc_id})

        for rt_id in rt_ids:
            if not any(rt.id == rt_id for rt in route_tables_by_id):
                raise AnsibleVPCException(
                    'Route table ID "{0}" does not exist'.format(rt_id))

    route_tables_by_name = []
    if rt_names:
        route_tables_by_name = vpc_conn.get_all_subnets(
            filters={'vpc_id': vpc_id, 'tag:Name': rt_names})

        for name in rt_names:
            matching = [rt.tags.get('Name') == name
                        for s in route_tables_by_name]
            if len(matching) == 0:
                raise AnsibleVPCException(
                    'Route table named "{0}" does not exist'.format(name))
            elif len(matching) > 1:
                raise AnsibleVPCException(
                    'Multiple route tables name "{0}"'.format(name))

    return route_tables_by_id + route_tables_by_name


def find_vpc(vpc_conn, vpc_id, vpc_name, cidr, resource_tags):
    """
    Finds a VPC that matches a specific id, name, or cidr + tags

    vpc_conn: Authenticated VPCConnection connection object
    vpc_id: The exact ID of the VPC
    vpc_name: The value of a VPC 'Name' tag to search
    cidr_block: The CIDR block VPCs whose tags to search
    resource_tags: A dict of tags to match against when used with `cidr_block`

    Returns:
    A VPC object that matches based on the search parameters
    """
    if not vpc_id and not vpc_name and not (cidr and resource_tags):
        raise AnsibleVPCException(
            'You must specify either a vpc_id, vpc_name, or a cidr block +'
            ' list of unique tags, aborting')

    found_vpcs = []

    if not found_vpcs and vpc_id:
        found_vpcs = vpc_conn.get_all_vpcs(filters={'vpc-id': vpc_id,
                                                    'state': 'available'})

    if not found_vpcs and vpc_name:
        found_vpcs = vpc_conn.get_all_vpcs(filters={'tag:Name': vpc_name})

    if not found_vpcs and (cidr and resource_tags):
        candidate_vpcs = vpc_conn.get_all_vpcs(None, {'cidr': cidr,
                                                      'state': 'available'})
        for vpc in candidate_vpcs:
            # Get all tags for each of the found VPCs
            vpc_tags = dict((t.name, t.value)
                            for t in vpc_conn.get_all_tags(
                                filters={'resource-id': vpc.id}))

            # If the supplied list of ID Tags match a subset of the VPC Tags,
            # we found our VPC
            if all((k in resource_tags and resource_tags[k] == v
                    for k, v in vpc_tags.items())):
                found_vpcs.append(vpc)

    if not found_vpcs:
        return None
    elif len(found_vpcs) == 1:
        return found_vpcs[0]

    raise AnsibleVPCException(
        'Found more than one VPC based on the supplied criteria, aborting')


def route_table_is_main(route_table):
    if route_table.id is None:
        return True
    for a in route_table.associations:
        if a.main:
            return True
    return False


def ensure_vpc_present(vpc_conn, vpc_id, vpc_name, cidr_block, resource_tags,
                       instance_tenancy, dns_support, dns_hostnames,
                       subnets, route_tables, wait,
                       wait_timeout, check_mode):
    """
    Creates a new VPC or modifies an existing one.

    vpc_conn: Authenticated VPCConnection connection object
    vpc_id: The exact ID of the VPC
    vpc_name: The value of a VPC 'Name' tag to search
    cidr_block: The CIDR block VPCs whose tags to search
    resource_tags: A dict of tags to match against and to update

    Returns:
        A dictionary with information about the VPC and subnets that were
        launched or modified.
    """
    changed = False

    # Check for existing VPC by cidr_block + tags or id
    vpc = find_vpc(vpc_conn, vpc_id, vpc_name, cidr_block, resource_tags)

    # Make sure Name tag is updated to vpc_name, if it's given and not
    # overridden in resource_tags.
    if vpc_name:
        if resource_tags is None:
            resource_tags = {}
        resource_tags.setdefault('Name', vpc_name)

    if vpc is None:
        if check_mode:
            return {'changed': True}

        changed = True
        try:
            vpc = vpc_conn.create_vpc(cidr_block, instance_tenancy)
            vpc_id = vpc.id

            # wait here until the vpc is available
            pending = True
            wait_timeout = time.time() + wait_timeout
            while wait and wait_timeout > time.time() and pending:
                try:
                    pvpc = vpc_conn.get_all_vpcs(vpc.id)
                    if hasattr(pvpc, 'state'):
                        if pvpc.state == 'available':
                            pending = False
                    elif hasattr(pvpc[0], 'state'):
                        if pvpc[0].state == "available":
                            pending = False
                # sometimes vpc_conn.create_vpc() will return a vpc that can't
                # be found yet by vpc_conn.get_all_vpcs() when that happens,
                # just wait a bit longer and try again
                except boto.exception.BotoServerError as e:
                    if e.error_code != 'InvalidVpcID.NotFound':
                        raise
                if pending:
                    time.sleep(5)
            if wait and wait_timeout <= time.time():
                raise AnsibleVPCException(
                    'Wait for VPC availability timeout on {0}'
                    .format(time.asctime())
                )
        except boto.exception.BotoServerError, e:
            raise AnsibleVPCException(
                '{0}: {1}'.format(e.error_code, e.error_message))

    # Done with base VPC, now change to attributes and features.

    # Add resource tags
    vpc_tags = dict(((t.name, t.value)
                     for t in vpc_conn.get_all_tags(
                         filters={'resource-id': vpc.id})))

    if (resource_tags and
            not set(resource_tags.items()).issubset(set(vpc_tags.items()))):
        new_tags = {}

        for key, value in set(resource_tags.items()):
            if (key, value) not in set(vpc_tags.items()):
                new_tags[key] = value

        if new_tags:
            vpc_conn.create_tags(vpc.id, new_tags, dry_run=check_mode)
            changed = True

    # boto doesn't appear to have a way to determine the existing
    # value of the dns attributes, so we just set them.
    # It also must be done one at a time.
    vpc_conn.modify_vpc_attribute(
        vpc.id, enable_dns_support=dns_support, dry_run=check_mode)
    vpc_conn.modify_vpc_attribute(
        vpc.id, enable_dns_hostnames=dns_hostnames, dry_run=check_mode)

    # Process all subnet properties
    listed_subnets = []
    if subnets is not None:
        listed_subnets = find_subnets(vpc_conn, vpc_id, subnets)
        current_subnets = vpc_conn.get_all_subnets(filters={'vpc_id': vpc.id})

        for subnet in listed_subnets:
            if not any(subnet.id == s.id for s in current_subnets):
                raise AnsibleVPCException(
                    'Unknown subnet {0}'.format(subnet_id, e))

        for subnet in current_subnets:
            if any(subnet.id == s.id for s in listed_subnets):
                continue

            try:
                vpc_conn.delete_subnet(subnet.id, dry_run=check_mode)
                changed = True
            except EC2ResponseError as e:
                raise AnsibleVPCException(
                    'Unable to delete subnet {0}, error: {1}'
                    .format(subnet.cidr_block, e))

    listed_route_tables = []
    if route_tables is not None:
        listed_route_tables = find_route_tables(vpc_conn, vpc_id, route_tables)
        # old ones except the 'main' route table as boto can't set the main
        # table yet.
        current_route_tables = vpc_conn.get_all_route_tables(
            filters={'vpc-id': vpc.id})

        for route_table in current_route_tables:
            if (any(route_table.id == rt.id for rt in listed_route_tables)
                    or route_table_is_main(route_table)):
                continue

            try:
                vpc_conn.delete_route_table(route_table.id, dry_run=check_mode)
                changed = True
            except EC2ResponseError, e:
                raise AnsibleVPCException(
                    'Unable to delete old route table {0}, error: {1}'
                    .format(route_table.id, e))

    return {
        'changed': changed,
        'vpc_id': vpc.id,
        'vpc': vpc_json(vpc),
        'subnets': [subnet_json(vpc_conn, s) for s in listed_subnets],
    }


def ensure_vpc_absent(vpc_conn, vpc_id, vpc_name, cidr, resource_tags,
                      check_mode):
    """
    Terminates a VPC.
    vpc_conn: Authenticated VPCConnection connection object
    vpc_id: The exact ID of the VPC
    vpc_name: The value of a VPC 'Name' tag to search
    cidr_block: The CIDR block VPCs whose tags to search
    resource_tags: A dict of tags to match against and to update

    Returns:
        A dictionary with information about the VPC that was terminated.
    """

    vpc = find_vpc(vpc_conn, vpc_id, vpc_name, cidr_block, resource_tags)

    changed = False
    if check_mode:
        if vpc is None:
            return {'changed': False, 'vpc_id': vpc_id, 'vpc': {}}
        elif vpc.state == 'available':
            changed = True
        else:
            changed = False
    elif vpc is None or vpc.state == 'available':
        changed = False
    else:
        changed = True
        try:
            subnets = vpc_conn.get_all_subnets(filters={'vpc_id': vpc.id})
            for sn in subnets:
                vpc_conn.delete_subnet(sn.id)

            igws = vpc_conn.get_all_internet_gateways(
                filters={'attachment.vpc-id': vpc.id}
            )
            for igw in igws:
                vpc_conn.detach_internet_gateway(igw.id, vpc.id)
                vpc_conn.delete_internet_gateway(igw.id)

            rts = vpc_conn.get_all_route_tables(filters={'vpc_id': vpc.id})
            for rt in rts:
                rta = rt.associations
                is_main = False
                for a in rta:
                    if a.main:
                        is_main = True
                if not is_main:
                    vpc_conn.delete_route_table(rt.id)

            vpc_conn.delete_vpc(vpc.id)
        except EC2ResponseError, e:
            raise AnsibleVPCException(
                'Unable to delete VPC {0}, error: {1}'.format(vpc.id, e)
            )

    return {'changed': changed, 'vpc_id': vpc.id, 'vpc': vpc_json(vpc)}


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        vpc_id=dict(required=False),
        vpc_name=dict(required=False),
        cidr_block=dict(required=False),
        resource_tags=dict(type='dict', required=False),
        instance_tenancy=dict(choices=['default', 'dedicated'],
                              default='default'),
        wait=dict(type='bool', default=False),
        wait_timeout=dict(type='int', default=300),
        dns_support=dict(type='bool', default=True),
        dns_hostnames=dict(type='bool', default=True),
        subnets=dict(type='list', required=False),
        route_tables=dict(type='list', required=False),
        state=dict(choices=['present', 'absent'], default='present'),
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    if not HAS_BOTO:
        module.fail_json(msg='boto is required for this module')

    vpc_id = module.params.get('vpc_id')
    vpc_name = module.params.get('vpc_name')
    cidr_block = module.params.get('cidr_block')
    instance_tenancy = module.params.get('instance_tenancy')
    dns_support = module.params.get('dns_support')
    dns_hostnames = module.params.get('dns_hostnames')
    subnets = module.params.get('subnets')
    route_tables = module.params.get('route_tables')
    resource_tags = module.params.get('resource_tags')
    wait = module.params.get('wait')
    wait_timeout = module.params.get('wait_timeout')
    state = module.params.get('state')

    ec2_url, aws_access_key, aws_secret_key, region = get_ec2_creds(module)
    if not region:
        module.fail_json(msg="region must be specified")

    try:
        vpc_conn = boto.vpc.connect_to_region(
            region,
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key
        )
    except boto.exception.NoAuthHandlerFound, e:
        module.fail_json(msg=str(e))

    try:
        if module.params.get('state') == 'absent':
            result = ensure_vpc_absent(
                vpc_conn=vpc_conn,
                vpc_id=vpc_id,
                vpc_name=vpc_name,
                cidr_block=cidr_block,
                resource_tags=resource_tags,
                check_mode=module.check_mode)
        elif state == 'present':
            result = ensure_vpc_present(
                vpc_conn=vpc_conn,
                vpc_id=vpc_id,
                vpc_name=vpc_name,
                cidr_block=cidr_block,
                resource_tags=resource_tags,
                instance_tenancy=instance_tenancy,
                dns_support=dns_support,
                dns_hostnames=dns_hostnames,
                subnets=subnets,
                route_tables=route_tables,
                wait=wait,
                wait_timeout=wait_timeout,
                check_mode=module.check_mode,
            )
    except AnsibleVPCException as e:
        module.fail_json(msg=str(e))

    module.exit_json(**result)


from ansible.module_utils.basic import *  # noqa
from ansible.module_utils.ec2 import *  # noqa

if __name__ == '__main__':
    main()
