# import getpass
# import os
# import libcloud.security
import time

from libcloud.compute.base import NodeImage
from libcloud.compute.base import NodeState
from libcloud.compute.providers import get_driver as compute_get_driver
from libcloud.compute.types import Provider as compute_Provider

from libcloud.loadbalancer.base import Member, Algorithm
from libcloud.loadbalancer.types import Provider as loadbalancer_Provider
from libcloud.loadbalancer.providers import get_driver as loadbalancer_get_driver

# reqs:
#   services: EC2 (nova, glance, neutron)
#   resources: 2 instances, 2 elastic ips (1 keypair, 2 security groups)

# The image to look for and use for the started instance
# ubuntu_image_name = 'ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-20200408'
ubuntu_image_id = "ami-085925f297f89fce1"  # local ami id for resent ubuntu 18.04 20200408 in us-west-1

# The public key to be used for SSH connection, please make sure, that you have the corresponding private key
#
# id_rsa.pub should look like this (standard sshd pubkey format):
# ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAw+J...F3w2mleybgT1w== user@HOSTNAME

keypair_name = 'emilde-pub'
pub_key_file = '~/Desktop/HS/Master/Semester2/CloudComputing/BP_Project/BP_Key2.pub'

flavor_name = 't2.nano'

# default region
# region_name = 'eu-central-1'
# region_name = 'ap-south-1'

# AWS Educate only allows us-east-1 see our AWS classroom at https://www.awseducate.com
# e.g., https://www.awseducate.com/student/s/launch-classroom?classroomId=a1v3m000005mNm6AAE

region_name = 'us-east-1'


def main():
    ###########################################################################
    #
    # get credentials
    #
    ###########################################################################

    # see AWS Educate classroom, Account Details

    # access_id = getpass.win_getpass("Enter your access_id:")
    # secret_key = getpass.win_getpass("Enter your secret_key:")
    # session_token = getpass.win_getpass("Enter your session_token:")
    # access_id = "ASIAU..."
    # secret_key = "7lafW..."
    # session_token = "IQoJb3JpZ...EMb//..."
    access_id = ""
    secret_key = ""
    session_token = ""

    ###########################################################################
    #
    # delete load balancer (Amazon AWS ELB)
    #
    ###########################################################################

    elb_provider = loadbalancer_get_driver(loadbalancer_Provider.ELB)
    elb_conn = elb_provider(access_id,
                            secret_key,
                            token=session_token,
                            region=region_name)

    print("Deleting previously created load balancers in: " + str(elb_conn.list_balancers()))
    for loadbalancer in elb_conn.list_balancers():
        if loadbalancer.name == "lb1":
            elb_conn.destroy_balancer(loadbalancer)

    ###########################################################################
    #
    # create EC2 connection
    #
    ###########################################################################

    provider = compute_get_driver(compute_Provider.EC2)
    conn = provider(key=access_id,
                    secret=secret_key,
                    token=session_token,
                    region=region_name)

    ###########################################################################
    #
    # clean up resources from previous demos
    #
    ###########################################################################

    # destroy running demo instances
    for instance in conn.list_nodes():
        if instance.name in ['all-in-one', 'app-worker-1', 'app-worker-2', 'app-worker-3', 'app-controller',
                             'app-services', 'app-api-1', 'app-api-2']:
            if instance.state is not NodeState.TERMINATED:
                print('Destroying Instance: %s' % instance.name)
                conn.destroy_node(instance)

    # wait until all nodes are destroyed to be able to remove depended security groups
    nodes_still_running = True
    while nodes_still_running:
        nodes_still_running = False
        time.sleep(3)
        instances = conn.list_nodes()
        for instance in instances:
            # if we see any demo instances still running continue to wait for them to stop
            if instance.name in ['all-in-one', 'app-worker-1', 'app-worker-2', 'app-controller', 'app-services']:
                if instance.state is not NodeState.TERMINATED:
                    nodes_still_running = True
        print('There are still instances running, waiting for them to be destroyed...')

    # delete security groups, respecting dependencies (hence deleting 'control' and 'services' first)
    for group in conn.ex_list_security_groups():
        if group in ['control', 'services']:
            print('Deleting security group: %s' % group)
            conn.ex_delete_security_group(group)

    # now we can delete security groups 'api' and 'worker', as 'control' and 'api' depended on them, otherwise AWS will
    # throw DependencyViolation: resource has a dependent object
    for group in conn.ex_list_security_groups():
        if group in ['api', 'worker']:
            print('Deleting security group: %s' % group)
            conn.ex_delete_security_group(group)


if __name__ == '__main__':
    main()
