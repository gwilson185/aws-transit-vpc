import logging
import time
import boto3
import json
from botocore.vendored import requests

dcx_client = boto3.client('directconnect')
log = logging.getLogger()
log.setLevel(logging.INFO)

SUCCESS = 'SUCCESS'
FAILED = 'FAILED'

#Network Connection definitions for EDC
vlan = 350
asn = 65000
BGPAuthKey = '0x9M3QVG.uNkgSjMZfViV7iF'
amazonAddress = '169.254.255.1/30'
customerAddress = '169.254.255.2/30'
addressFamily = 'ipv4'

def lambda_handler(event, context):

  if (event.RequestType == 'Delete'):
    response = send(event, context, SUCCESS, {}, None)
  elif (event.RequestType == 'Create'):
      response = send(event, context, createPrivateVIF(vgw, event['StackId'],vlan,asn,BGPAuthKey,amazonAddress,customerAddress,addressFamily))

  return {'Response' : response}

def send(event, context, responseStatus, responseData, physicalResourceId):
  responseUrl = event['ResponseURL']

  log.info('Event: ' + str(event))
  log.info('ResponseURL: ' + responseUrl)

  responseBody = {}
  responseBody['Status'] = responseStatus
  responseBody['Reason'] = 'See the details in CloudWatch Log Stream: ' + context.log_stream_name
  responseBody['PhysicalResourceId'] = physicalResourceId or context.log_stream_name
  responseBody['StackId'] = event['StackId']
  responseBody['RequestId'] = event['RequestId']
  responseBody['LogicalResourceId'] = event['LogicalResourceId']
  responseBody['Data'] = responseData

  json_responseBody = json.dumps(responseBody)

  log.info('Response body: ' + str(json_responseBody))

  headers = {
  'content-type' : '',
  'content-length' : str(len(json_responseBody))
}

  try:
   response = requests.put(responseUrl,
data=json_responseBody,headers=headers)
   log.info('Status code: ' + str(response.reason))
   return SUCCESS
  except Exception as e:
   log.error('send(..) failed executing requests.put(..): ' + str(e))
   return FAILED

def createPrivateVIF(vgw, stackid, vlan, asn, BGPAuthKey, amazonAddress, customerAddress, addressFamily):
    vifcreate = dcx_client.create_private_virtual_interface(connectionId=getConnectionId(),newPrivateVirtualInterface={
        'virtualInterfaceName' : stackid,
        'vlan' : vlan,
        'asn' : asn,
        'authKey' : BGPAuthKey,
        'amazonAddress' : amazonAddress,
        'customerAddress' : customerAddress,
        'addressFamily' : addressFamily,
        'virtualGatewayId' : vgw })

    while getVIFStatus(vifcreate['connectId'],vifcreate['virtualInterfaceID']) == 'pending':
        time.sleep(5)

    if getVIFStatus(vifcreate['connectId'],vifcreate['virtualInterfaceID']) == 'available':
        return SUCCESS
    else: return FAILED

def getConnectionId():
    resp = dcx_client.describe_connections()
    if len(resp['connections']) == 1:
     connection = resp['connections'][0]
     log.info('DirectConnect Connection ID %s Found', connection['connectionId'])
     return connection['connectionId']
    else:
     log.error('Not enough Logic to determine DCX Connection ID')

def getVIFStatus(connectionId, vif_id):
    resp = dcx_client.describe_virtual_interfaces(connectionId=connectionId,virtualInterfaceId=vif_id)
    if len(resp['virtualInterfaces']) == 1:
        vif = resp['virtualInterfaces'][0]
        return vif['virtualInterfaceState']