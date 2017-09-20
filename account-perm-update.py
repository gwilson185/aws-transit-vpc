import boto3
import json
import logging
from datetime import datetime
from dateutil.tz import tzutc
from botocore.exceptions import ClientError

log = logging.getLogger()
log.setLevel(logging.DEBUG)

#value added from Cloud Formation
policyarn = '%POLICY_ARN%'
policyarn = 'arn:aws:iam::228198000189:policy/TransitPollerXAccount'


#boto3.setup_default_session(profile_name='edc-transit')

iam = boto3.client('iam')

#Returns policy body for an inline policy in the role
def get_managed_policy(policyarn):
    try:
        response = iam.get_policy(PolicyArn=policyarn)

    except ClientError, err:
        #log.error(err)
        print err

    policy = iam.get_policy_version(PolicyArn=response['Policy']['Arn'],VersionId=response['Policy']['DefaultVersionId'])
    return json.dumps(policy['PolicyVersion']['Document'])


def iam_policy_list(policy):
    policy_list = list()
    policy = json.loads(policy)
    for item in range(0,len(policy['Statement'])):
        policy_list.append(policy['Statement'][item]['Resource'].split(':')[4])
    return policy_list


def account_id_list():
    try:

        mgmt_client = boto3.client('sts')

    except Exception, e:
        print str(e)

    response = mgmt_client.assume_role( RoleArn="arn:aws:iam::660369111642:role/ListOrganizations",
                                            RoleSessionName="mgmt_session",
                                            DurationSeconds=900)
    #print response

    try:
        master_client = boto3.client('organizations',
                                            aws_access_key_id=response['Credentials']['AccessKeyId'],
                                            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                                            aws_session_token=response['Credentials']['SessionToken'] )

    except Exception, e:
        print str(e)

    paginator = master_client.get_paginator('list_accounts')
    response_iter = paginator.paginate()

    account_list = list()
    for page in response_iter:
        for account in page['Accounts']:
            account_list.append(account['Id'])

    return account_list


def remove_policy_element(policy,account_list):

    for acct in account_list:
      for item in range(0, len(policy['Statement'])):
        if acct in str(policy['Statement'][item]):
          policy['Statement'].pop(item)
    return policy


def add_policy_element(policy,account_list):

    for acct in account_list:
        policy['Statement'].append({u'Action': u'sts:AssumeRole',
                                    u'Resource': u'arn:aws:iam::' + acct + ':role/TransitAccountPollerRole',
                                    u'Effect': u'Allow'})
    return policy


def delete_old_policy_version(policyarn):
    versions = iam.list_policy_versions(PolicyArn=policyarn)['Versions']
    date = datetime.now(tzutc())
    versionid = None

    for ver in versions:
        if ver['CreateDate'] <= date:
            versionid = ver['VersionId']
            date = ver['CreateDate']
    print versionid, date


    try:
        iam.delete_policy_version(PolicyArn=policyarn,VersionId=versionid)

    except ClientError, err:
        print err.response['Error']['Message']
        log.error('Error deleting policy version: %s Version ID: $s',policyarn.split('/')[1],versionid)
        log.debug('Boto3 Exception attempting to delete policy version. %s %s',err.response['Error']['Code'],err.response['Error']['Message'])
    else:
        print 'deleted policy version'
        log.info('Deleted policy version %s in Policy %s',versionid,policyarn.split('/')[1])


def pushIamPolicy(policyarn, policy):
    for attempt in range(3):
        try:
            iam.create_policy_version(PolicyArn=policyarn, PolicyDocument=policy,SetAsDefault=True)

        except ClientError as err:
            if err.response['Error']['Code'] == 'LimitExceeded':
                delete_old_policy_version(policyarn)
            else:
                log.debug('Boto3 Exception attempting to add policy version. %s %s',err.response['Error']['Code'],err.response['Error']['Message'])
                continue
        else:
            log.info('Added new policy version Policy %s',policyarn.split('/')[1])
            #print 'Added new policy version'
            return


def lambda_handler(event,context):
    policyUpdate = False

    #get managed policy details
    iamPolicy = get_managed_policy(policyarn)

    #generate account list from current policy
    currentPolicyList = iam_policy_list(iamPolicy)

    #get full AWS Account list from master account
    AccountList = account_id_list()

    #determines which accounts need to be added
    AddAccounts = list(set(AccountList) - set(currentPolicyList))

    #determine which accounts need to deleted from the policy
    RemoveAccounts = list(set(currentPolicyList) - set(AccountList))

    newIamPolicy = json.loads(iamPolicy)

    if RemoveAccounts != []:
      newIamPolicy = remove_policy_element(newIamPolicy,RemoveAccounts)
      policyUpdate = True

    if AddAccounts != []:
      newIamPolicy = add_policy_element(newIamPolicy,AddAccounts)
      policyUpdate = True

    if policyUpdate:
        pushIamPolicy(policyarn,json.dumps(newIamPolicy))


