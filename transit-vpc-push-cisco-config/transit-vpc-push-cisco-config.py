######################################################################################################################
#  Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.                                           #
#                                                                                                                    #
#  Licensed under the Amazon Software License (the "License"). You may not use this file except in compliance        #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://aws.amazon.com/asl/                                                                                    #
#                                                                                                                    #   
#  or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError
import paramiko
import json
from xml.dom import minidom
import ast
import time
import os
import string
import logging
from boto3.dynamodb.conditions import Key, Attr
log = logging.getLogger()
log.setLevel(logging.INFO)

config_file='transit_vpc_config.txt'

#Entrust VPN termination IPs; used to determine if summary routes should be added
EDC_DCX_ENDPOINT = '10.0.252.18'
EDC_PUBLIC_ENDPOINT = '204.124.81.200'

ddb_vpn_value = dict()

#These S3 endpoint URLs are provided to support VPC endpoints for S3 in regions such as Frankfort that require explicit region endpoint definition
endpoint_url = {
  "us-east-1" : "https://s3.amazonaws.com",
  "us-east-2" : "https://s3-us-east-2.amazonaws.com",
  "us-west-1" : "https://s3-us-west-1.amazonaws.com",
  "us-west-2" : "https://s3-us-west-2.amazonaws.com",
  "eu-west-1" : "https://s3-eu-west-1.amazonaws.com",
  "eu-west-2" : "https://s3-eu-west-2.amazonaws.com",
  "eu-central-1" : "https://s3-eu-central-1.amazonaws.com",
  "ca-central-1" : "https://s3-ca-central-1.amazonaws.com",
  "ap-northeast-1" : "https://s3-ap-northeast-1.amazonaws.com",
  "ap-northeast-2" : "https://s3-ap-northeast-2.amazonaws.com",
  "ap-south-1" : "https://s3-ap-south-1.amazonaws.com",
  "ap-southeast-1" : "https://s3-ap-southeast-1.amazonaws.com",
  "ap-southeast-2" : "https://s3-ap-southeast-2.amazonaws.com",
  "sa-east-1" : "https://s3-sa-east-1.amazonaws.com"
}

#Logic to determine when the prompt has been discovered
def prompt(chan):
    buff = ''
    while not buff.endswith('#'):
        resp = chan.recv(9999)
        buff += resp
        #log.debug("%s",resp)
    return buff

# Logic to figure out the next availble tunnel
def getNextTunnelId(ssh):
    log.debug('Start getNextTunnelId')
    ssh.send('term len 0\n')
    log.debug("%s",prompt(ssh))
    ssh.send('config t\n')
    log.debug("%s",prompt(ssh))
    ssh.send('do show int summary | include Tunnel\n')
    output = prompt(ssh)
    log.debug("%s",output)
    ssh.send('exit\n')
    log.debug("%s",prompt(ssh))
    lastTunnelNum=''
    for line in output.split('\n'):
        line=line.replace('* Tunnel','Tunnel')
        log.debug("%s",line)
        if line.strip()[:6] == 'Tunnel':
            lastTunnelNum = line.strip().partition(' ')[0].replace('Tunnel','')

    if lastTunnelNum == '':
        return 1
    return int(lastTunnelNum) + 1


def getNextRouteId(ssh,bgp_asn):
    log.info('Start getNextRouteId')
    ssh.send('term len 0\n')
    log.debug("%s",prompt(ssh))
    #ssh.send('config t\n')
    #log.debug("%s",prompt(ssh))
    ssh.send('sh run | include rd ' + str(bgp_asn) + '\n')
    log.info('Ran command for Route Domain list on Router')
    output = prompt(ssh)
    log.debug("%s",output)
    #ssh.send('exit\n')
    #log.info("%s",prompt(ssh))
    lastRouteNum = 0
    output = output.split('\n')
    #Removes StdIn line and the last line which is the command prompt
    log.debug("Output with EOL removed: %s", output)
    output = output[1:-1]
    log.debug("Output after [1:-1]: %s", output)
    #lines = [line.lstrip(':') for line in output]
    existingRD = [x.strip().split(':')[1] for x in output]
    log.debug("Routing IDs found %s",existingRD)
    existingRD.sort()
    for rd in existingRD:
        if int(rd) == lastRouteNum:
            lastRouteNum = lastRouteNum + 1
    log.info('New Route Domain ID is %s',lastRouteNum)
    return str(lastRouteNum)

# Logic to figure out existing tunnel IDs
def getExistingTunnelId(ssh,vpn_connection_id):
    log.debug('Start getExistingTunnelId')
    ssh.send('term len 0\n')
    log.debug("%s",prompt(ssh))
    #ssh.send('config t\n')
    #log.debug("%s",prompt(ssh))
    #Display keyrings so we can derive tunnelId
    ssh.send('show run | include crypto keyring\n')
    output = prompt(ssh)
    log.debug("%s",output)
    tunnelNum=0
    #Now parse crypto keyring lines for keyring-vpn-connection_id-tunnelId
    for line in output.split('\n'):
      if vpn_connection_id in line:
        tmpNum = int(line.split('-')[-1])
        if tunnelNum < tmpNum:
          tunnelNum = tmpNum

    if tunnelNum == 0:
      log.error('Unable to find existing tunnels for %s', vpn_connection_id)
      return 0
    #Parsing logic gets the greater of the two tunnel numbers, so return tunnelNum -1 to get the first tunnel number
    return tunnelNum-1

#Generic logic to push pre-generated Cisco config to the router
def pushConfig(ssh,config):
    log.info("Starting to push config")
    log.debug("%s",config)
    #ssh.send('term len 0\n')
    #prompt(ssh)
    ssh.send('config t\n')
    log.debug("%s",prompt(ssh))
    stime = time.time()
    for line in config:
      if line == "WAIT":
        log.debug("Waiting 30 seconds...")
        time.sleep(30)
      else:
        ssh.send(line+'\n')
        log.debug("%s",prompt(ssh))
    ssh.send('exit\n')
    log.debug("%s",prompt(ssh))
    log.debug("   --- %s seconds ---", (time.time() - stime))
    log.info("Saving config!")
    ssh.send('copy run start\n\n\n\n\n')
    log.info("%s",prompt(ssh))
    log.info("Update complete!")

#Logic to determine the bucket prefix from the S3 key name that was provided
def getBucketPrefix(bucket_name, bucket_key):
    #Figure out prefix from known bucket_name and bucket_key
    bucket_prefix = '/'.join(bucket_key.split('/')[:-2])
    if len(bucket_prefix) > 0:
        bucket_prefix += '/'
    return bucket_prefix

#Logic to download the transit VPC configuration file from S3
def getTransitConfig(bucket_name, bucket_prefix, s3_url, config_file):
    s3=boto3.client('s3', endpoint_url=s3_url,
      config=Config(s3={'addressing_style': 'virtual'}, signature_version='s3v4'))
    log.info("Downloading config file: %s/%s/%s%s", s3_url, bucket_name, bucket_prefix,config_file)
    return ast.literal_eval(s3.get_object(Bucket=bucket_name,Key=bucket_prefix+config_file)['Body'].read())

#Logic to upload a new/updated transit VPC configuration file to S3 (not currently used)
def putTransitConfig(bucket_name, bucket_prefix, s3_url, config_file, config):
    s3=boto3.client('s3', endpoint_url=s3_url,
      config=Config(s3={'addressing_style': 'virtual'}, signature_version='s3v4'))
    log.info("Uploading new config file: %s/%s/%s%s", s3_url,bucket_name, bucket_prefix,config_file)
    s3.put_object(Bucket=bucket_name,Key=bucket_prefix+config_file,Body=str(config))

#Logic to download the SSH private key from S3 to be used for SSH public key authentication
def downloadPrivateKey(bucket_name, bucket_prefix, s3_url, prikey):
    if os.path.exists('/tmp/'+prikey):
        os.remove('/tmp/'+prikey)
    s3=boto3.client('s3', endpoint_url=s3_url,
      config=Config(s3={'addressing_style': 'virtual'}, signature_version='s3v4'))
    log.info("Downloading private key: %s/%s/%s%s",s3_url, bucket_name, bucket_prefix, prikey)
    s3.download_file(bucket_name,bucket_prefix+prikey, '/tmp/'+prikey)

def create_peer_config(bucket_name,bucket_key,s3_url):
    log.info("Creating Peering Config...")
    log.info("Processing %s/%s", bucket_name, bucket_key)
    peering_config = []
    # Download the VPN configuration XML document
    s3 = boto3.client('s3', endpoint_url=s3_url,config=Config(s3={'addressing_style': 'virtual'}, signature_version='s3v4'))

    try:
        config = s3.get_object(Bucket=bucket_name, Key=bucket_key)

    except ClientError as err:
        log.error("Could not get VPN Config file: %s", err)
        return None
    body = config['Body'].read()
    peering_config = body.splitlines()
    log.debug("New Peering config: %s",peering_config)
    return peering_config


#Logic to create the appropriate Cisco configuration
def create_cisco_config(bucket_name, bucket_key, s3_url, bgp_asn, ssh):
    log.info("Processing %s/%s", bucket_name, bucket_key)

    #Download the VPN configuration XML document
    s3=boto3.client('s3',endpoint_url=s3_url,
      config=Config(s3={'addressing_style': 'virtual'}, signature_version='s3v4'))

    try: config=s3.get_object(Bucket=bucket_name,Key=bucket_key)

    except ClientError as err:
        log.error("Could not get VPN Config file: %s",err)
        return

    xmldoc=minidom.parseString(config['Body'].read())
    #Extract transit_vpc_configuration values
    vpn_config = xmldoc.getElementsByTagName("transit_vpc_config")[0]
    account_id = vpn_config.getElementsByTagName("account_id")[0].firstChild.data
    vpn_endpoint = vpn_config.getElementsByTagName("vpn_endpoint")[0].firstChild.data
    vpn_status = vpn_config.getElementsByTagName("status")[0].firstChild.data
    preferred_path = vpn_config.getElementsByTagName("preferred_path")[0].firstChild.data
    routedomain_asn = vpn_config.getElementsByTagName("domain_asn")[0].firstChild.data

    #Extract VPN connection information
    vpn_connection=xmldoc.getElementsByTagName('vpn_connection')[0]
    vpn_connection_id=vpn_connection.attributes['id'].value
    customer_gateway_id=vpn_connection.getElementsByTagName("customer_gateway_id")[0].firstChild.data
    vpn_gateway_id=vpn_connection.getElementsByTagName("vpn_gateway_id")[0].firstChild.data
    vpn_connection_type=vpn_connection.getElementsByTagName("vpn_connection_type")[0].firstChild.data

    #Establish values to update Routing Database
    global ddb_vpn_value
    ddb_vpn_value['vpnconnectionid']= vpn_connection_id
    ddb_vpn_value['routedomain'] = vpn_config.getElementsByTagName("route_domain")[0].firstChild.data

    #Determine the VPN tunnels to work with
    if vpn_status == 'create':    
      tunnelId=getNextTunnelId(ssh)
      ddb_vpn_value['action'] = 'add'
    else:
      tunnelId=getExistingTunnelId(ssh,vpn_connection_id)
      if tunnelId == 0:
        return None
      
    log.info("%s %s with tunnel #%s and #%s.",vpn_status, vpn_connection_id, tunnelId, tunnelId+1)
    # Create or delete the VRF for this connection
    if vpn_status == 'delete':
      ddb_vpn_value['action'] = 'delete'
      ipsec_tunnel = vpn_connection.getElementsByTagName("ipsec_tunnel")[0]
      customer_gateway=ipsec_tunnel.getElementsByTagName("customer_gateway")[0]
      customer_gateway_bgp_asn=customer_gateway.getElementsByTagName("bgp")[0].getElementsByTagName("asn")[0].firstChild.data
      #Remove VPN configuration for both tunnels
      config_text = ['router bgp {}'.format(customer_gateway_bgp_asn)]
      config_text.append('  no address-family ipv4 vrf {}'.format(vpn_connection_id))
      config_text.append('exit')
      config_text.append('no ip vrf {}'.format(vpn_connection_id))
      config_text.append('interface Tunnel{}'.format(tunnelId))
      config_text.append('  shutdown')
      config_text.append('exit')
      config_text.append('no interface Tunnel{}'.format(tunnelId))
      config_text.append('interface Tunnel{}'.format(tunnelId+1))
      config_text.append('  shutdown')
      config_text.append('exit')
      config_text.append('no interface Tunnel{}'.format(tunnelId+1))
      config_text.append('no route-map rm-{} permit'.format(vpn_connection_id))
      # Cisco requires waiting 60 seconds before removing the isakmp profile
      config_text.append('WAIT')
      config_text.append('WAIT')
      config_text.append('no crypto isakmp profile isakmp-{}-{}'.format(vpn_connection_id,tunnelId))
      config_text.append('no crypto isakmp profile isakmp-{}-{}'.format(vpn_connection_id,tunnelId+1))
      config_text.append('no crypto keyring keyring-{}-{}'.format(vpn_connection_id,tunnelId))
      config_text.append('no crypto keyring keyring-{}-{}'.format(vpn_connection_id,tunnelId+1))
    else:
      # Create global tunnel configuration
      config_text = ['ip vrf {}'.format(vpn_connection_id)]
      config_text.append(' rd {}:{}'.format(bgp_asn, getNextRouteId(ssh,bgp_asn)))
      config_text.append(' route-target export {}'.format(routedomain_asn))
      config_text.append(' route-target import {}'.format(routedomain_asn))
      config_text.append(' import map rm-vrfimport')
      config_text.append('exit')
      # Check to see if a route map is needed for creating a preferred path
      if preferred_path != 'none':
        config_text.append('route-map rm-{} permit'.format(vpn_connection_id))
        # If the preferred path is this transit VPC vpn endpoint, then set a shorter as-path prepend than if it is not
        if preferred_path == vpn_endpoint:
          config_text.append('  set as-path prepend {}'.format(bgp_asn))
        else:
          config_text.append('  set as-path prepend {} {}'.format(bgp_asn, bgp_asn))
        config_text.append('exit')

      # Create tunnel specific configuration
      for ipsec_tunnel in vpn_connection.getElementsByTagName("ipsec_tunnel"):
            customer_gateway=ipsec_tunnel.getElementsByTagName("customer_gateway")[0]
            customer_gateway_tunnel_outside_address=customer_gateway.getElementsByTagName("tunnel_outside_address")[0].getElementsByTagName("ip_address")[0].firstChild.data
            customer_gateway_tunnel_inside_address_ip_address=customer_gateway.getElementsByTagName("tunnel_inside_address")[0].getElementsByTagName("ip_address")[0].firstChild.data
            customer_gateway_tunnel_inside_address_network_mask=customer_gateway.getElementsByTagName("tunnel_inside_address")[0].getElementsByTagName("network_mask")[0].firstChild.data
            customer_gateway_tunnel_inside_address_network_cidr=customer_gateway.getElementsByTagName("tunnel_inside_address")[0].getElementsByTagName("network_cidr")[0].firstChild.data
            customer_gateway_bgp_asn=customer_gateway.getElementsByTagName("bgp")[0].getElementsByTagName("asn")[0].firstChild.data
            customer_gateway_bgp_hold_time=customer_gateway.getElementsByTagName("bgp")[0].getElementsByTagName("hold_time")[0].firstChild.data

            vpn_gateway=ipsec_tunnel.getElementsByTagName("vpn_gateway")[0]
            vpn_gateway_tunnel_outside_address=vpn_gateway.getElementsByTagName("tunnel_outside_address")[0].getElementsByTagName("ip_address")[0].firstChild.data
            vpn_gateway_tunnel_inside_address_ip_address=vpn_gateway.getElementsByTagName("tunnel_inside_address")[0].getElementsByTagName("ip_address")[0].firstChild.data
            vpn_gateway_tunnel_inside_address_network_mask=vpn_gateway.getElementsByTagName("tunnel_inside_address")[0].getElementsByTagName("network_mask")[0].firstChild.data
            vpn_gateway_tunnel_inside_address_network_cidr=vpn_gateway.getElementsByTagName("tunnel_inside_address")[0].getElementsByTagName("network_cidr")[0].firstChild.data
            vpn_gateway_bgp_asn=vpn_gateway.getElementsByTagName("bgp")[0].getElementsByTagName("asn")[0].firstChild.data
            vpn_gateway_bgp_hold_time=vpn_gateway.getElementsByTagName("bgp")[0].getElementsByTagName("hold_time")[0].firstChild.data

            ike=ipsec_tunnel.getElementsByTagName("ike")[0]
            ike_authentication_protocol=ike.getElementsByTagName("authentication_protocol")[0].firstChild.data
            ike_encryption_protocol=ike.getElementsByTagName("encryption_protocol")[0].firstChild.data
            ike_lifetime=ike.getElementsByTagName("lifetime")[0].firstChild.data
            ike_perfect_forward_secrecy=ike.getElementsByTagName("perfect_forward_secrecy")[0].firstChild.data
            ike_mode=ike.getElementsByTagName("mode")[0].firstChild.data
            ike_pre_shared_key=ike.getElementsByTagName("pre_shared_key")[0].firstChild.data

            ipsec=ipsec_tunnel.getElementsByTagName("ipsec")[0]
            ipsec_protocol=ipsec.getElementsByTagName("protocol")[0].firstChild.data
            ipsec_authentication_protocol=ipsec.getElementsByTagName("authentication_protocol")[0].firstChild.data
            ipsec_encryption_protocol=ipsec.getElementsByTagName("encryption_protocol")[0].firstChild.data
            ipsec_lifetime=ipsec.getElementsByTagName("lifetime")[0].firstChild.data
            ipsec_perfect_forward_secrecy=ipsec.getElementsByTagName("perfect_forward_secrecy")[0].firstChild.data
            ipsec_mode=ipsec.getElementsByTagName("mode")[0].firstChild.data
            ipsec_clear_df_bit=ipsec.getElementsByTagName("clear_df_bit")[0].firstChild.data
            ipsec_fragmentation_before_encryption=ipsec.getElementsByTagName("fragmentation_before_encryption")[0].firstChild.data
            ipsec_tcp_mss_adjustment=ipsec.getElementsByTagName("tcp_mss_adjustment")[0].firstChild.data
            ipsec_dead_peer_detection_interval=ipsec.getElementsByTagName("dead_peer_detection")[0].getElementsByTagName("interval")[0].firstChild.data
            ipsec_dead_peer_detection_retries=ipsec.getElementsByTagName("dead_peer_detection")[0].getElementsByTagName("retries")[0].firstChild.data

            config_text.append('crypto keyring keyring-{}-{}'.format(vpn_connection_id,tunnelId))
            config_text.append('  local-address GigabitEthernet1')
            config_text.append('  pre-shared-key address {} key {}'.format(vpn_gateway_tunnel_outside_address, ike_pre_shared_key))
            config_text.append('exit')
            config_text.append('crypto isakmp profile isakmp-{}-{}'.format(vpn_connection_id,tunnelId))
            config_text.append('  local-address GigabitEthernet1')
            config_text.append('  match identity address {}'.format(vpn_gateway_tunnel_outside_address))
            config_text.append('  keyring keyring-{}-{}'.format(vpn_connection_id,tunnelId))
            config_text.append('exit')
            config_text.append('interface Tunnel{}'.format(tunnelId))
            config_text.append('  description {} from {} to {} for account {}'.format(vpn_connection_id, vpn_gateway_id, customer_gateway_id, account_id))
            config_text.append('  ip vrf forwarding {}'.format(vpn_connection_id))
            config_text.append('  ip address {} 255.255.255.252'.format(customer_gateway_tunnel_inside_address_ip_address))
            config_text.append('  ip virtual-reassembly')
            config_text.append('  tunnel source GigabitEthernet1')
            config_text.append('  tunnel destination {} '.format(vpn_gateway_tunnel_outside_address))
            config_text.append('  tunnel mode ipsec ipv4')
            config_text.append('  tunnel protection ipsec profile ipsec-vpn-aws')
            config_text.append('  ip tcp adjust-mss 1387')
            config_text.append('  no shutdown')
            config_text.append('exit')
            config_text.append('router bgp {}'.format(customer_gateway_bgp_asn))
            config_text.append('  address-family ipv4 vrf {}'.format(vpn_connection_id))
            #Summary routes are added to keep the number of routes sent to VPCs limited. AWS has a 100 route hard limit
            config_text.append('  aggregate-address 10.0.0.0 255.0.0.0 as-set summary-only')
            config_text.append('  aggregate-address 172.16.0.0 255.240.0.0 as-set summary-only')
            config_text.append('  aggregate-address 192.168.0.0 255.255.0.0 as-set summary-only')

            config_text.append('  neighbor {} remote-as {}'.format(vpn_gateway_tunnel_inside_address_ip_address, vpn_gateway_bgp_asn))
            if preferred_path != 'none':
              config_text.append('  neighbor {} route-map rm-{} out'.format(vpn_gateway_tunnel_inside_address_ip_address, vpn_connection_id))
            if vpn_gateway_tunnel_outside_address == EDC_DCX_ENDPOINT:
                config_text.append('  neighbor {} route-map rm-localpref in'.format(vpn_gateway_tunnel_inside_address_ip_address))
            if vpn_gateway_tunnel_outside_address == EDC_PUBLIC_ENDPOINT:
                config_text.append('  neighbor {} route-map rm-prepend out'.format(vpn_gateway_tunnel_inside_address_ip_address))
            if vpn_gateway_tunnel_outside_address == EDC_DCX_ENDPOINT or vpn_gateway_tunnel_outside_address == EDC_PUBLIC_ENDPOINT:
                config_text.append('  neighbor {} send-community both'.format(vpn_gateway_tunnel_inside_address_ip_address))
                config_text.append('  neighbor {} prefix-list no-aggregate out'.format(vpn_gateway_tunnel_inside_address_ip_address))
                config_text.append('  neighbor {} prefix-list no-aggregate in'.format(vpn_gateway_tunnel_inside_address_ip_address))
                config_text.append('  no aggregate-address 10.0.0.0 255.0.0.0 as-set summary-only')
                config_text.append('  no aggregate-address 172.16.0.0 255.240.0.0 as-set summary-only')
                config_text.append('  no aggregate-address 192.168.0.0 255.255.0.0 as-set summary-only')
            config_text.append('  neighbor {} timers 10 30 30'.format(vpn_gateway_tunnel_inside_address_ip_address))
            config_text.append('  neighbor {} activate'.format(vpn_gateway_tunnel_inside_address_ip_address))
            config_text.append('  neighbor {} as-override'.format(vpn_gateway_tunnel_inside_address_ip_address))
            config_text.append('  neighbor {} soft-reconfiguration inbound'.format(vpn_gateway_tunnel_inside_address_ip_address))
            config_text.append('exit')
            config_text.append('exit')

            #Increment tunnel ID for going onto the next tunnel
            tunnelId+=1
        
    log.debug("Conversion complete")
    return config_text


def create_route_config(bucket_name,bucket_prefix, bucket_key, s3_url, config, ssh, csr_name):
    #Connect to DynamoDB
    rdomain_db = boto3.resource('dynamodb')
    rdomain_table = rdomain_db.Table(config['RD_LIST'])
    s3 = boto3.client('s3', endpoint_url=s3_url,
                      config=Config(s3={'addressing_style': 'virtual'}, signature_version='s3v4'))
    #returns records without vrf_asn attribute
    rd = rdomain_table.scan(FilterExpression=Attr('vrf_asn').not_exists())
    log.info('Found %s Domains that need Routing Domain ASN IDs generated',(json.dumps(rd['Count'])))
    if int(json.dumps(rd['Count'])) > 0:
        for x in range(0, int(json.dumps(rd['Count']))):
            d = json.loads(json.dumps(rd['Items'][x]))
            log.info('Getting New Route ID')
            nextRouteID = str(config['BGP_ASN']) + ':' + getNextRouteId(ssh,config['BGP_ASN'])
            log.info('Updating DynamoDb with new ASN')
            update = rdomain_table.update_item(Key={'rd_name': d['rd_name']}, UpdateExpression="set vrf_asn = :asn",
                                               ExpressionAttributeValues={':asn': nextRouteID}, ReturnValues="UPDATED_NEW")
            log.info('DynamoDB update completed...')
            if update['Attributes']['vrf_asn'] == nextRouteID:
                log.info('Successfully updated DynamoDB Table %s Route Domain %s with BGP ASN Domain ID %s',config['RD_LIST'],d['rd_name'],update['Attributes']['vrf_asn'])
                route_config=['ip vrf {}'.format(d['rd_name'])]
                route_config.append('rd {}'.format(nextRouteID))
                route_config.append('route-target import {}'.format(nextRouteID))
                route_config.append('route-target export {}'.format(nextRouteID))
                route_config.append('exit')

                s3.delete_object(Bucket=bucket_name,Key=bucket_key)
                return route_config
            else:
                log.error('Error updating DynamoDB Table %s Route Domain %s with BGP ASN Domain ID %s',config['RD_LIST'],d['rd_name'],update['Attributes']['vrf_asn'])
                return ''


def get_route_config(bucket_name,bucket_key,s3_url):
    s3 = boto3.client('s3', endpoint_url=s3_url,
                      config=Config(s3={'addressing_style': 'virtual'}, signature_version='s3v4'))
    config = s3.get_object(Bucket=bucket_name,Key=bucket_key)
    return(config['Body'].read)


def updateVPNDatabase(action,table,vpnconnectionid,csrname,routedomain):
    rdomain_db = boto3.resource('dynamodb')
    rdomain_table = rdomain_db.Table(table)

    try: rdomain_table.update_item(Key={'rd_name': routedomain}, UpdateExpression=action + "#asc :vpn",
                                       ExpressionAttributeNames={'#asc': csrname + '_Associated_VPNs'},
                                       ExpressionAttributeValues={':vpn': set([vpnconnectionid])}, ReturnValues="UPDATED_NEW")
    except ClientError as err:
        print err


def lambda_handler(event, context):
    record=event['Records'][0]
    bucket_name=record['s3']['bucket']['name']
    bucket_key=record['s3']['object']['key']
    bucket_region=record['awsRegion']
    log.info('The bucket key is %s',bucket_key)
    bucket_prefix=getBucketPrefix(bucket_name, bucket_key)
    log.debug("Getting config")
    stime = time.time()
    config = getTransitConfig(bucket_name, bucket_prefix, endpoint_url[bucket_region], config_file)

    if 'CSR1' in bucket_key:
        csr_ip = config['PIP1']
        csr_name = 'CSR1'
    elif 'CSR2' in bucket_key:
        csr_ip = config['PIP2']
        csr_name = 'CSR2'
    log.info("--- %s seconds ---", (time.time() - stime))
    #Download private key file from secure S3 bucket
    downloadPrivateKey(bucket_name, bucket_prefix, endpoint_url[bucket_region], config['PRIVATE_KEY'])
    log.debug("Reading downloaded private key into memory.")
    k = paramiko.RSAKey.from_private_key_file("/tmp/"+config['PRIVATE_KEY'])
    #Delete the temp copy of the private key
    os.remove("/tmp/"+config['PRIVATE_KEY'])
    log.debug("Deleted downloaded private key.")

    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if 'newroute' in bucket_key:
        stime = time.time()
        log.info('Pushing Route config to router %s.', csr_name)
        try:
            c.connect(hostname=csr_ip, username=config['USER_NAME'], pkey=k)
            PubKeyAuth = True
        except paramiko.ssh_exception.AuthenticationException:
            log.error("PubKey Authentication Failed! Connecting with password")
            c.connect(hostname=csr_ip, username=config['USER_NAME'], password=config['PASSWORD'])
            PubKeyAuth = False
        log.info("--- %s seconds ---", (time.time() - stime))
        log.debug("Connected to %s", csr_ip)
        ssh = c.invoke_shell()
        csr_config = create_route_config(bucket_name, bucket_prefix, bucket_key, endpoint_url[bucket_region], config, ssh, csr_name)
        pushConfig(ssh, csr_config)
        ssh.close()
        if csr_name == 'CSR1':
            csr_name = 'CSR2'
            csr_ip = config['PIP2']
        else:
            csr_name = 'CSR1'
            csr_ip = config['PIP1']
        log.info("Connecting to %s (%s)", csr_name, csr_ip)
        stime = time.time()
        try:
            c.connect(hostname=csr_ip, username=config['USER_NAME'], pkey=k)
            PubKeyAuth = True
        except paramiko.ssh_exception.AuthenticationException:
            log.error("PubKey Authentication Failed! Connecting with password")
            c.connect(hostname=csr_ip, username=config['USER_NAME'], password=config['PASSWORD'])
            PubKeyAuth = False
        log.info("--- %s seconds ---", (time.time() - stime))
        log.debug("Connected to %s", csr_ip)
        ssh = c.invoke_shell()
        log.info('Pushing Route config to router %s.', csr_name)
        pushConfig(ssh, csr_config)
        log.info("--- %s seconds ---", (time.time() - stime))
    else:
        log.info("Connecting to %s (%s)", csr_name, csr_ip)
        stime = time.time()
        try:
          c.connect( hostname = csr_ip, username = config['USER_NAME'], pkey = k )
          PubKeyAuth=True
        except paramiko.ssh_exception.AuthenticationException:
          log.error("PubKey Authentication Failed! Connecting with password")
          c.connect( hostname = csr_ip, username = config['USER_NAME'], password = config['PASSWORD'] )
          PubKeyAuth=False
        log.info("--- %s seconds ---", (time.time() - stime))
        log.debug("Connected to %s",csr_ip)
        ssh = c.invoke_shell()
        log.debug("%s",prompt(ssh))
        log.debug("Creating config.")
        stime = time.time()
        if 'peer' in bucket_key:
            csr_config = create_peer_config(bucket_name, bucket_key,endpoint_url[bucket_region])
        else:
            csr_config = create_cisco_config(bucket_name, bucket_key,endpoint_url[bucket_region], config['BGP_ASN'], ssh)
        log.info("--- %s seconds ---", (time.time() - stime))
        if csr_config != None:
            log.info("Pushing config to router.")
            stime = time.time()
            pushConfig(ssh,csr_config)
            log.info("--- %s seconds ---", (time.time() - stime))
            ssh.close()
        else:
            log.error("There is not a valid configuration to push to the router!")
            log.debug("%s",csr_config)
        if ddb_vpn_value != {}:
            updateVPNDatabase(ddb_vpn_value['action'], config['RD_LIST'], ddb_vpn_value['vpnconnectionid'], csr_name,
                              ddb_vpn_value['routedomain'])
        else:
            log.info("No Update to Database made.")

    return
