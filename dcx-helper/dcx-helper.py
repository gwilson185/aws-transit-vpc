import json
import logging
import time
import boto3
from botocore.vendored import requests
from botocore.exceptions import ClientError

dcx_client = boto3.client('directconnect')
log = logging.getLogger()
log.setLevel(logging.DEBUG)

SUCCESS = 'SUCCESS'
FAILED = 'FAILED'

#Network Connection definitions for EDC


def lambda_handler(event, context):

    log.debug("Received event: %s", event)

    if (event['RequestType'] == 'Delete'):
        delresp = deleteVIF(event['PhysicalResourceId'])
        response = send(event, context, delresp['Status'], {}, None)

    elif (event['RequestType'] == 'Create'):
        vifresponse = createPrivateVIF(event)
        response = send(event, context, vifresponse['Status'],{'DCXVifId': vifresponse['virtualInterfaceId']},vifresponse['virtualInterfaceId'])

    elif (event['RequestType'] == 'Update'):
        delresp=deleteVIF(event['PhysicalResourceId'])
        if delresp['Status'] == SUCCESS:
          while getVIFStatus(event['PhysicalResourceId']) in ['deleting','None']:
              time.sleep(5)
        vifresponse = createPrivateVIF(event)
        response = send(event, context, vifresponse['Status'], {'DCXVifId': vifresponse['virtualInterfaceId']},
                    vifresponse['virtualInterfaceId'])

    return {'Response' : response}

def send(event, context, responseStatus, responseData, physicalResourceId):
  responseUrl = event['ResponseURL']

  log.info('Event: ' + str(event))
  log.info('ResponseURL: ' + responseUrl)

  responseBody = {}
  responseBody['Status'] = responseStatus
  responseBody['Reason'] = 'See the details in CloudWatch Log Stream: ' + context.log_stream_name
  responseBody['PhysicalResourceId'] = physicalResourceId
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
                                      data=json_responseBody, headers=headers)
   log.info('Status code: ' + str(response.reason))
   return SUCCESS
  except Exception as e:
   log.error('send(..) failed executing requests.put(..): ' + str(e))
   return FAILED

def createPrivateVIF(event):
    try:
        vifcreate = dcx_client.create_private_virtual_interface(connectionId=getConnectionId(),newPrivateVirtualInterface={
        'virtualInterfaceName' : event['StackId'].split('/')[1],
        'vlan' : int(event['ResourceProperties']['VLAN']),
        'asn' : int(event['ResourceProperties']['ASN']),
        'authKey' : event['ResourceProperties']['BGPAuthKey'],
        'amazonAddress' : event['ResourceProperties']['AmazonAddress'],
        'customerAddress' : event['ResourceProperties']['CustomerAddress'],
        'addressFamily' : event['ResourceProperties']['AddressFamily'],
        'virtualGatewayId' : event['ResourceProperties']['VGW'] })
    except ClientError as err:
        if err.response['Error']['Code'] == 'DirectConnectClientException':
          log.error("VIF Creation failed: %s",err.response['Error']['Message'])
          return {'Status': FAILED, 'virtualInterfaceId': ''}

    log.info("Created DCX VIF: %s", vifcreate['virtualInterfaceId'])
    return {'Status': SUCCESS, 'virtualInterfaceId': vifcreate['virtualInterfaceId']}

def deleteVIF(vif_id):
    try:

       dcx_client.delete_virtual_interface(virtualInterfaceId=vif_id)

    except ClientError as err:
        if err.response['Error']['Code'] == 'DirectConnectClientException':
            log.debug("%s",err.response)
            log.error("Could not delete Direct Connect Virtual Interface %s: ", vif_id,err.response['Error']['Message'])
            return {'Status': FAILED}


    return {'Status': SUCCESS}

def getConnectionId():
    resp = dcx_client.describe_connections()
    if len(resp['connections']) == 1:
     connection = resp['connections'][0]
     log.info('DirectConnect Connection ID %s Found', connection['connectionId'])
     return connection['connectionId']
    else:
     log.error('Not enough Logic to determine DCX Connection ID')


def getVIFStatus(vif_id):
    resp = dcx_client.describe_virtual_interfaces(virtualInterfaceId=vif_id)
    if len(resp['virtualInterfaces']) == 1:
        vif = resp['virtualInterfaces'][0]
        log.info("Virtual Interface %s State: %s",vif_id,vif['virtualInterfaceState'])
        return vif['virtualInterfaceState']
    else:
        return 'None'