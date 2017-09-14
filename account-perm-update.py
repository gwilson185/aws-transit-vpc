import boto3
import json
from botocore.exceptions import ClientError

s3bucket = 'qa2-vpnconfigs3bucket-18znizdedfl0n'
s3prefix = 'vpnconfigs'
kmskeyid = ''
kmskeyname = ''

boto3.setup_default_session(profile_name='edc-transit')

s3 = boto3.client('s3')
#kms = boto3.client('kms')

def bucket_policy_list(bucket_policy):
    policy_list = list()
    policy = json.loads(bucket_policy['Policy'])
    for item in range(1,len(policy['Statement'])):
        policy_list.append(policy['Statement'][item]['Principal']['AWS'].split(':')[4])
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

def remove_bucket_policy_element(bucket_policy,account_list):

    for acct in account_list:
      for item in range(1, len(bucket_policy['Statement'])):
        if acct in str(bucket_policy['Statement'][item]):
          bucket_policy['Statement'].pop(item)
    return bucket_policy

def add_bucket_policy_element(bucket_policy,account_list,s3bucket,s3prefix):

    for acct in account_list:
        bucket_policy['Statement'].append({u'Action': [u's3:GetObject', u's3:PutObject', u's3:PutObjectAcl'],
                                    u'Resource': u'arn:aws:s3:::' + s3bucket + '/' + s3prefix + '/*',
                                    u'Effect': u'Allow', u'Principal': {u'AWS': u'arn:aws:iam::' + acct + ':root'}})
    return bucket_policy

def pushBucketPolicy(bucket_policy,s3bucket):
    try:
        s3.put_bucket_policy(Bucket=s3bucket, Policy=bucket_policy)

    except ClientError as err:
          print err.response['Error']['Message']


bucket_policy = s3.get_bucket_policy(Bucket=s3bucket)
#kms_policy = kms.get_key_policy(KeyId='',PolicyName='default')

policyUpdate = False

currentBucketPolicyList = bucket_policy_list(bucket_policy)
AccountList = account_id_list()

AddAccounts = list(set(AccountList) - set(currentBucketPolicyList))
RemoveAccounts = list(set(currentBucketPolicyList) - set(AccountList))

newBucketPolicy = json.loads(bucket_policy['Policy'])

if RemoveAccounts != []:
  newBucketPolicy = remove_bucket_policy_element(newBucketPolicy,RemoveAccounts)
  policyUpdate = True

if AddAccounts != []:
  newBucketPolicy = add_bucket_policy_element(newBucketPolicy,AddAccounts,s3bucket,s3prefix)
  policyUpdate = True

if policyUpdate:
    pushBucketPolicy(json.dumps(newBucketPolicy),s3bucket)
    print json.dumps(newBucketPolicy)

print policyUpdate