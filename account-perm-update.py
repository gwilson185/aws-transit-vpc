import boto3
import json
import logging

from botocore.exceptions import ClientError

log = logging.getLogger()
log.setLevel(logging.DEBUG)


rolename = '%ROLE_NAME%'
policyname= 'TransitPollerXAccount'



iam = boto3.client('iam')
#add region_name value

#Returns policy body for an inline policy in the role
def get_managed_policy(rolename,policyname):
    try:
        response = iam.get_role_policy(RoleName=rolename,PolicyName=policyname)

    except ClientError, err:
        log.error(err)

    else:
        log.info('Found policy %s',policyname)
        return response['PolicyDocument']


def iam_policy_list(policy):
    policy_list = list()
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
    list = []
    for acct in account_list:
        for item in range(len(policy['Statement'])):
            if acct in str(policy['Statement'][item]):
                print policy['Statement'][item]
                list.append(item)
    list.sort(reverse=True)
    print list
    for l in list:
        policy['Statement'].pop(l)
    return policy


def add_policy_element(policy,account_list):

    for acct in account_list:
        policy['Statement'].append({u'Action': u'sts:AssumeRole',
                                    u'Resource': u'arn:aws:iam::' + acct + ':role/TransitXAccountPollerRole',
                                    u'Effect': u'Allow'})
    return policy


def pushIamPolicy(rolename,policyname, policy):
        try:
            iam.put_role_policy(RoleName=rolename, PolicyName=policyname, PolicyDocument=policy)

        except ClientError as err:
            print err
            #log.debug('Boto3 Exception attempting to add policy version. %s', err)

        else:
            #log.info('Added new policy version to Role %s',rolename)
            return


def lambda_handler(event,context):
    policyUpdate = False

    #get managed policy details
    iamPolicy = get_managed_policy(rolename,policyname)

    #generate account list from current policy
    currentPolicyList = iam_policy_list(iamPolicy)

    #get full AWS Account list from master account
    AccountList = account_id_list()

    #determines which accounts need to be added
    AddAccounts = list(set(AccountList) - set(currentPolicyList))

    #determine which accounts need to deleted from the policy
    RemoveAccounts = list(set(currentPolicyList) - set(AccountList))

    newIamPolicy = iamPolicy

    if RemoveAccounts != []:
       # log.info('Accounts to be removed: %s', RemoveAccounts)
        newIamPolicy = remove_policy_element(newIamPolicy,RemoveAccounts)
        policyUpdate = True

    if AddAccounts != []:
       # log.info('Accounts to be added: %s', AddAccounts)
        newIamPolicy = add_policy_element(newIamPolicy,AddAccounts)
        policyUpdate = True

    if policyUpdate:
        pushIamPolicy(rolename,policyname,json.dumps(newIamPolicy))
        log.info('Policy %s has been updated',policyname)
    else:
         log.info('No Policy updates were needed at this time.')
         return


