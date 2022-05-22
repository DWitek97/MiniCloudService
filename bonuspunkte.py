# this is the script for the bonuspoints --> based on "demo4-scale-out-lb-in-aws.py"

import getpass
# import os
from libcloud.compute.base import NodeImage
from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider

# reqs:
#   services: EC2 (nova, glance, neutron)
#   resources: 2 instances, 2 elastic ips (1 keypair, 2 security groups)

# The image to look for and use for the started instance
# ubuntu_image_name = 'ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-20200408'
ubuntu_image_id = "ami-0747bdcabd34c712a" # local ami id for resent ubuntu 18.04 20200408 in eu-central-1

# The public key to be used for SSH connection, please make sure, that you have the corresponding private key
#
# id_rsa.pub should look like this (standard sshd pubkey format):
# ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAw+J...F3w2mleybgT1w== user@HOSTNAME

# --------------------------------------------------------------------------------------------------------------------#
# TODO use correct keys (this one works for me)
# --------------------------------------------------------------------------------------------------------------------#
#keypair_name = 'david-pub'
#pub_key_file = '~/.ssh/id_rsa.pub'
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

    # -----------------------------------------------------------------------------------------------------------------#
    # TODO get new AWS credentials every time!
    #------------------------------------------------------------------------------------------------------------------#

    # access_id = getpass.win_getpass("Enter your access_id:")
    # secret_key = getpass.win_getpass("Enter your secret_key:")
    # session_token = getpass.win_getpass("Enter your session_token:")
    # !!!!!!!!!!!!!!!!!!!!!!!!!!!muss bei jeder sitzung neu geholt werden
    access_id = ""
    secret_key = ""
    session_token = ""

    ###########################################################################
    #
    # create connection
    #
    ###########################################################################

    provider = get_driver(Provider.EC2)
    conn = provider(access_id,
                    secret_key,
                    token=session_token,
                    region=region_name)

    ###########################################################################
    #
    # get image, flavor, network for instance creation
    #
    ###########################################################################

    #("Fetching images (AMI) list from AWS region. This will take a lot of seconds (AWS has a very long list of "
          #"supported operating systems and versions)... please be patient...")
    # images = conn.list_images()

    # image = ''
    # for img in images:
    #   # if img.name == ubuntu_image_name:
    #   if img.extra['owner_alias'] == 'amazon':
    #       print(img)
    #   if img.id == ubuntu_image_name:
    #       image = img

    image = NodeImage(id=ubuntu_image_id, name=None, driver=conn)

    # fetch/select the image referenced with ubuntu_image_name above
    #image = [i for i in images if i.name == ubuntu_image_name][0]
    #print(image)

    flavors = conn.list_sizes()
    flavor = [s for s in flavors if s.id == flavor_name][0]
    print(flavor)

    # networks = conn.ex_list_networks()
    # network = ''
    # for net in networks:
    #    if net.name == project_network:
    #        network = net

    ###########################################################################
    #
    # create keypair dependency
    #
    ###########################################################################

    print('Checking for existing SSH key pair...')
    keypair_exists = False
    for keypair in conn.list_key_pairs():
        if keypair.name == keypair_name:
            keypair_exists = True

    if keypair_exists:
        print('Keypair ' + keypair_name + ' already exists. Skipping import.')
    else:
        print('adding keypair...')
        conn.import_key_pair_from_file(keypair_name, pub_key_file)

    # nur zum spass
    for keypair in conn.list_key_pairs():
        print(keypair)

    ###########################################################################
    #
    # create security group dependency
    #
    ###########################################################################

    print('Checking for existing worker security group...')
    worker_security_group_exists = False
    worker_security_group_name = 'worker'
    for security_group in conn.ex_get_security_groups():
        if security_group.name == worker_security_group_name:
            worker_security_group_id = security_group.id
            worker_security_group_exists = True

    if worker_security_group_exists:
        print('Worker Security Group ' + worker_security_group_name + ' already exists. Skipping creation.')
    else:
        worker_security_group_result = conn.ex_create_security_group('worker', 'for services that run on a worker node')
        worker_security_group_id = worker_security_group_result['group_id']
        conn.ex_authorize_security_group_ingress(worker_security_group_id, 22, 22, cidr_ips=['0.0.0.0/0'],
                                                 protocol='tcp')

    print('Checking for existing controller security group...')
    controller_security_group_exists = False
    controller_security_group_name = 'control'
    controller_security_group_id = ''
    for security_group in conn.ex_get_security_groups():
        if security_group.name == controller_security_group_name:
            controller_security_group_id = security_group.id
            controller_security_group_exists = True

    if controller_security_group_exists:
        print('Controller Security Group ' + controller_security_group_name + ' already exists. Skipping creation.')
    else:
        controller_security_group_result = conn.ex_create_security_group('control',
                                                                         'for services that run on a control node')
        controller_security_group_id = controller_security_group_result['group_id']
        conn.ex_authorize_security_group_ingress(controller_security_group_id, 22, 22, cidr_ips=['0.0.0.0/0'],
                                                 protocol='tcp')
        conn.ex_authorize_security_group_ingress(controller_security_group_id, 80, 80, cidr_ips=['0.0.0.0/0'],
                                                 protocol='tcp')
        conn.ex_authorize_security_group_ingress(controller_security_group_id, 443, 443, cidr_ips=['0.0.0.0/0'],
                                                 protocol='tcp')
        # conn.ex_authorize_security_group_ingress(controller_security_group_id, 5672, 5672,
        #                                         group_pairs=[{'group_id': worker_security_group_id}], protocol='tcp')

    # for security_group in conn.ex_list_security_groups():
    #    print(security_group)

    ###########################################################################
    #
    # create app-controller
    #
    ###########################################################################

    # https://git.openstack.org/cgit/openstack/faafo/plain/contrib/install.sh
    # is currently broken, hence the "rabbitctl" lines were added in the example
    # below, see also https://bugs.launchpad.net/faafo/+bug/1679710
    #
    # Thanks to Stefan Friedmann for finding this fix ;)

    userdata = '''#!/bin/bash

# 2. Update Linux apt:
sudo apt-get update
echo "update"

# 6. Install nginx server:
# sudo apt-get install -y nginx
sudo apt-get install -y apache2
sudo apt-get install -y apache2-utils
sudo ufw allow 'Apache'
echo "apache installed."

# 7. Add private SSH Key
ssh_private_key="-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAyWqR8pKdpFza4+IaOAoPKDOCcLzQBZRQKqdaXE5DqbBl05nx
two4fdop+YAGBhI+mIU2VkQjhlh5ymDk5lUr+SkItRpPUDNheY52L4LejW3UqyJH
HzaHeXmknQqbXdEFjfRVzfGIYDFUo9zj8dyVcXqOMBLlu3SmIT3niQQnCJzK1fHI
4jyAh4l0MFDcOVYnj5+q5CxTk6ci8f8nxmXLzTzZfp/cZ3FgpN0xCr4cklvuWmY2
losEUSbTS6J7fNr2dAdY4yPGVMAPGwt2nM7Otsfg+mE5/AeuYAmos7Z62ey8kOIt
+7iZ8I3zkG0JqwDSDo5XDUmgji2OKKq0MeZyGQIDAQABAoIBAG/UNrJKyzHtyC6M
Y+hHVYEJkFvNyWW/of78qgPkBFdbtD2XFIh/KTxe+70mYrHOQWjnVXLyJBM8XmqJ
/60PDvoo2UfMEstBq9YUzfO1IqG9oD1gK8LdwLwmWMpEkFy3Z/EX/uf4ObLG0Oqm
Av1Pbr3xwK5aX6kDrBV6zGnbn1x8zKg5zEOR8HTg20fOou2bwYiTUjxibgqPMvN6
wjk3LUFVj8fU8sKyud6cZVARt+4z5/Y5BiXnf3KPEVbxhgC/7xfBHrrrGf3l3xZv
FwWix+IbkfePRX1T6R9U4FtDNlLdYYjoha4CBUJyx3OZxNdA/1MGTRrba/Q8vY+v
jBhiuHECgYEA8/f0ck/dk5xhuLHpFjJTxRioeKVd91yhhVRiSDfA9hFFmN6jTihB
0n+HjqiS7QpdNdI2VmxrfowegF7lmVk6rGXMBcRESduSLLL9VTlc2A8YfH9a3N7F
revd1vdIvS9cFZ9MY/IF02yi0maceG/XtmhsdfgDKFGTblXadJXbC10CgYEA01ln
HPg+PQo28vMlSkWFkwAJ9EWZAdZU5uZFLZhNACstTFYUq0qxQBW2wKr+IzLWtXpI
9ihv5oHRpuSkFWs6BcywDdBWTVJSwBs5/IR2zN10QHGlF0E6N6U6xZlPgyifL0LY
MWZAj0Fenh4pk7xOE0w1HQKdDLOqZhdCyaHO0e0CgYEAkEE58emVa7WY9puD5hMG
A1GsNAIbyKql+u9FWcxVtWnLDDQAvbMCEJRFtC2rCqwJJ0zPwlRDT0VMt7zk58Kh
9dQPSg2eD0ncab/AGYdchYiPgvXO5TB4FHmV54i6ItsBCOvzQFmX5kajE+OGe5Qu
KXYfQ7XNMCbkFOaA0FTXeyUCgYAWLxkqqkfmIk9YOvtcC2YU4vkogbGoxrWMsvjp
60WR0fZkP9jVjfaC8oSHPquESE7PJ7HG3MG6IUA/U1qBwQqLF0wXdxnH7e8vqOvy
PHk30brlFMiuYzNYKei8WvZEnxvuWwbUUJZQMx1aXXIhxq8vSV192QthDO7C3ogt
H+XUlQKBgCYIbtsXKzTyHsE9Ma9XQJqkqvc5WTzGhyqISChtlBZoGYpInyxiOUZ9
xNSYlAdSWaiyZ0VffCWXmnXbQd8bLjz2LBLgtH2v+sJpl2W5zDCrCmhu5x8RefA0
UcervOBwyZo7UL9IJJPI2Lz9mJrfNT9pG0zK72HEnTVLsCtpmdhx
-----END RSA PRIVATE KEY-----"

echo "$ssh_private_key" | sudo tee /root/.ssh/id_rsa_github
# echo "$ssh_private_key" | sudo tee ~/.ssh/id_rsa_github
chmod 600 /root/.ssh/id_rsa_github
eval $(ssh-agent)
ssh-add /root/.ssh/id_rsa_github
# ssh-add ~/.ssh/id_rsa_github
echo "ssh private key successfully added"

# 8. Download/Copy GitHub Repo:
ssh-keyscan -H github.com >> /root/.ssh/known_hosts
# ssh-keyscan -H github.com >> ~/.ssh/known_hosts

# ---------------------------------------------- TODO ----------------------------------------------------------------#
# TODO hier unser eigenes Git Repo mit kleiner Webanwendung
git clone git@github.com:Lizzylizard/WebAppBPCC.git ~/TeamProject-SoSe21-TeamB
# https://github.com/Darya-del/TeamProject-SoSe21-TeamB.git
#git@github.com:Lizzylizard/WebAppBPCC.git
# --------------------------------------------------------------------------------------------------------------------#

sudo mv ~/TeamProject-SoSe21-TeamB/index.html ../../var/www/html
sudo mv ~/TeamProject-SoSe21-TeamB/app.js ../../var/www/html

sudo rm -r ../../var/www/html/index.nginx-debian.html

sudo chmod +x ../../var/www/html/app.js
sudo chmod +x ../../var/www/html/index.html


# loadbalancer (ELB bei amazon) deployen für 2. 5 punkte (aufpassen, immer wieder loeschen!)
# demo4-scale-out-lb-in-aws.py --> davon parts nehmen

    '''

    print('Starting new app-controller instance and wait until it is running...')
    instance_controller_1 = conn.create_node(name='app-controller',
                                             image=image,
                                             size=flavor,
                                             ex_keyname=keypair_name,
                                             ex_userdata=userdata,
                                             ex_security_groups=[controller_security_group_name])

    conn.wait_until_running(nodes=[instance_controller_1], timeout=120, ssh_interface='public_ips')
    # warte laenger damit public ips gefuellt ist
    # oder liste alle instanzen mit py programm (list instances in libcloud)
    print("Public ips are = ", instance_controller_1.public_ips)

    ###########################################################################
    #
    # assign app-controller elastic ip
    #
    ###########################################################################

    # AWS offers elastic ips, that have the same function as floating IPs in OpenStack. However elastic IPs cost money,
    # and instances typically already have public IP in AWS, what a luxury ;)
    '''print('Checking for unused Elastic IP...')
    unused_elastic_ip = None
    for elastic_ip in conn.ex_describe_all_addresses():
        if not elastic_ip.instance_id:
            unused_elastic_ip = elastic_ip
            break

    if not unused_elastic_ip:
        print('Allocating new Elastic IP')
        unused_elastic_ip = conn.ex_allocate_address()
    conn.ex_associate_address_with_node(instance_controller_1, unused_elastic_ip)
    print('Controller Application will be deployed to http://%s' % unused_elastic_ip.ip) '''

    ###########################################################################
    #
    # getting id and ip address of app-controller instance
    #
    ###########################################################################

    # instance should not have a public ip? floating ips are assigned later
    # instance_controller_1 = conn.ex_get_node_details(instance_controller_1.id)
    # if instance_controller_1.public_ips:
    #    ip_controller = instance_controller_1.public_ips[0]
    # else:
    ip_controller = instance_controller_1.private_ips[0]

    ###########################################################################
    #
    # create app-worker-1
    #
    ###########################################################################
    '''
    # userdata = '''#!/usr/bin/env bash
   # curl -L -s https://gogs.informatik.hs-fulda.de/srieger/cloud-computing-msc-ai-examples/raw/master/faafo/contrib/install.sh | bash -s -- \
    #    -i faafo -r worker -e 'http://%(ip_controller)s' -m 'amqp://faafo:guest@%(ip_controller)s:5672/'
    ''' % {'ip_controller': ip_controller}

    print('Starting new app-worker-1 instance and wait until it is running...')
    instance_worker_1 = conn.create_node(name='app-worker-1',
                                         image=image,
                                         size=flavor,
                                         ex_keyname=keypair_name,
                                         ex_userdata=userdata,
                                         ex_security_groups=[worker_security_group_name])

    conn.wait_until_running(nodes=[instance_worker_1], timeout=120, ssh_interface='public_ips')

    ###########################################################################
    #
    # assign app-worker elastic ip
    #
    ###########################################################################

    # AWS offers elastic ips, that have the same function as floating IPs in OpenStack. However elastic IPs cost money,
    # and instances typically already have public IP in AWS, what a luxury ;)
    print('Checking for unused Elastic IP...')
    unused_elastic_ip = None
    for elastic_ip in conn.ex_describe_all_addresses():
        if not elastic_ip.instance_id:
            unused_elastic_ip = elastic_ip
            break

    if not unused_elastic_ip:
        print('Allocating new Elastic IP')
        unused_elastic_ip = conn.ex_allocate_address()
    conn.ex_associate_address_with_node(instance_worker_1, unused_elastic_ip)
    print('The worker will be available for SSH at %s' % unused_elastic_ip.ip)

    print('You can use ssh to login to the controller using your private key. After login, you can list available '
          'fractals using "faafo list". To request the generation of new fractals, you can use "faafo create". '
          'You can also see other options to use the faafo example cloud service using "faafo -h".') '''


if __name__ == '__main__':
    main()
