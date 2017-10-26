import boto3
import ast
from botocore.client import Config
#boto3.setup_default_session(profile_name='edc-transit')
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr
import logging

log = logging.getLogger()
log.setLevel(logging.DEBUG)


bucket_name='%BUCKET_NAME%'
bucket_prefix='%PREFIX%'

rdomain_db = boto3.resource('dynamodb')

#update = rdomain_table.update_item(Key={'rd_name': d['rd_name']},UpdateExpression="ADD #asc :vpn",ExpressionAttributeNames={"#asc": "Associated_VPNs"},ExpressionAttributeValues={':vpn': set([vpnname])}, ReturnValues="UPDATED_NEW")


def updateVPNDatabase(action,table,vpnconnectionid,csrname,routedomain):
    try: table.update_item(Key={'rd_name': routedomain}, UpdateExpression=action + "#asc :vpn",
                                       ExpressionAttributeNames={'#asc': csrname + '_Associated_VPNs'},
                                       ExpressionAttributeValues={':vpn': set([vpnconnectionid])}, ReturnValues="UPDATED_NEW")
    except ClientError as err:
        print err


def peer_list(table):
    #Returns a list of routing domains that have Peer defined
    peers = table.scan(FilterExpression="attribute_exists(Peers)")

    return peers['Items']


def peer_validate(table,peer):
    rd = table.query(KeyConditionExpression=Key('rd_name').eq(peer))
    if rd['Count'] == 1:
        return True
    else:
        return False


def get_peer_asn(table,routingdomain):
    rd = table.query(KeyConditionExpression=Key('rd_name').eq(routingdomain))
    return rd['Items'][0]['vrf_asn']


def peer_config(router,table):
    config = []
    for rd in peer_list(table):
        for peer in rd['Peers']:
            if peer_validate(table,peer):
                for vpn in rd[router + '_Associated_VPNs']:
                    config.append('ip vrf {}'.format(vpn))
                    config.append('route-target import {}'.format(get_peer_asn(table,peer)))
                    config.append('exit')
    return config


def lambda_handler(event,context):
    s3 = boto3.client('s3', config=Config(signature_version='s3v4'))
    log.info('Getting config file %s/%s%s', bucket_name, bucket_prefix, 'transit_vpc_config.txt')
    env_config = ast.literal_eval(
        s3.get_object(Bucket=bucket_name, Key=bucket_prefix + 'transit_vpc_config.txt')['Body'].read())
    rdomain_table = rdomain_db.Table(env_config['RD_LIST'])
    for router in ('CSR1','CSR2'):
        config = peer_config(router,rdomain_table)
        log.info('Peering Build is Complete')
        log.info('%s',config)
        s3 = boto3.resource('s3')
        s3.put_object( Body=config,Bucket=bucket_name,Key=bucket_prefix + router +'/' + 'peering.conf',ACL='bucket-owner-full-control',ServerSideEncryption='aws:kms',SSEKMSKeyId=env_config['KMS_KEY'])
        print config
