import json
import logging
import time

import dcx_helper.boto3
import dcx_helper.requests
from dcx_helper.botocore.vendored import dcx_helper
.requests

dcx_client = dcx_helper.boto3.client('directconnect')
log = logging.getLogger()
log.setLevel(logging.DEBUG)

SUCCESS = 'SUCCESS'
FAILED = 'FAILED'

#Network Connection definitions for EDC


def lambda_handler(event, context):

    log.debug("Recieved event: %s", event)
    if (event['RequestType'] == 'Delete'):
        #Waiting to see if I can get VifID back from CLoud Formation
        delresp = deleteVIF(event['ResourceProperties']['VGW'])
        response = send(event, context, delresp['Status'], {}, None)
    elif (event['RequestType'] == 'Create'):
        vifresponse = createPrivateVIF(event)
        response = send(event, context, vifresponse['Status'],{'DCXVifId': vifresponse['virtualInterfaceID']})

    return {'Response' : response}

def send(event, context, responseStatus, responseData, physicalResourceId):
  responseUrl = event['ResponseURL']

  log.info('Event: ' + str(event))
  log.info('ResponseURL: ' + responseUrl)

  responseBody = {}
  responseBody['Status'] = responseStatus
  responseBody['Reason'] = 'See the details in CloudWatch Log Stream: ' + context['log_stream_name']
  responseBody['PhysicalResourceId'] = physicalResourceId or context['log_stream_name']
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
   response = dcx_helper.requests.put(responseUrl,
                                      data=json_responseBody, headers=headers)
   log.info('Status code: ' + str(response.reason))
   return SUCCESS
  except Exception as e:
   log.error('send(..) failed executing requests.put(..): ' + str(e))
   return FAILED

def createPrivateVIF(event):
    vifcreate = dcx_client.create_private_virtual_interface(connectionId=getConnectionId(),newPrivateVirtualInterface={
        'virtualInterfaceName' : 'VIF-' + event['Stackid'].split[1],
        'vlan' : event['ResourceProperties']['VLAN'],
        'asn' : event['ResourceProperties']['ASN'],
        'authKey' : event['ResourceProperties']['BGPAuthKey'],
        'amazonAddress' : event['ResourceProperties']['AmazonAddress'],
        'customerAddress' : event['ResourceProperties']['CustomerAddress'],
        'addressFamily' : event['ResourceProperties']['AddressFamily'],
        'virtualGatewayId' : event['ResourceProperties']['VGW'] })
    log.debug("Created DCX VIF: %s", vifcreate)

    while getVIFStatus(vifcreate['virtualInterfaceID']) == 'pending':
        log.debug("waiting 5 seconds for change in status....")
        time.sleep(5)

    if getVIFStatus(vifcreate['virtualInterfaceID']) == 'available':
        log.info("VIF is available.")
        return {'Status': SUCCESS, 'VIF_ID': vifcreate['virtualInterfaceID']}
    else:
        log.info("VIF Creation failed!")
        return {'Status': FAILED, 'VIF_ID': vifcreate['virtualInterfaceID']}

def deleteVIF(vgw):
    vifdelete = dcx_client.delete_virtual_interface(virtualInterfaceId=findVifID(vgw))
    while getVIFStatus(vifdelete['virtualInterfaceID']) == 'deleting':
        log.debug("waiting 5 seconds for change in status....")
        time.sleep(5)

    if getVIFStatus(vifdelete['virtualInterfaceID']) == 'deleted':
        log.info("VIF Deleted...")
        return {'Status': SUCCESS}
    else:
        log.info("VIF deletion failed!")
        return {'Status': FAILED}

def getConnectionId():
    resp = dcx_client.describe_connections()
    if len(resp['connections']) == 1:
     connection = resp['connections'][0]
     log.info('DirectConnect Connection ID %s Found', connection['connectionId'])
     return connection['connectionId']
    else:
     log.error('Not enough Logic to determine DCX Connection ID')

def findVifId(vgw):
    resp = dcx_client.describe_virtual_interfaces()
    for vif in resp['virtualInterfaces']:
      if vif['virtualGatewayId'] == vgw:
        log.info('DirectConnect Virtual Interface ID %s Found', vif['virtualInterfaceId'])
        return vif['virtualInterfaceId']

def getVIFStatus(vif_id):
    resp = dcx_client.describe_virtual_interfaces(virtualInterfaceId=vif_id)
    if len(resp['virtualInterfaces']) == 1:
        vif = resp['virtualInterfaces'][0]
        return vif['virtualInterfaceState']