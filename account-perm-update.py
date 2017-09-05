import boto3
import json

s3bucket = 'qa2-vpnconfigs3bucket-18znizdedfl0n'

boto3.setup_default_session(profile_name='edc-transit')

s3 = boto3.client('s3')


try:

    mgmt_client = boto3.client('sts')

except Exception, e:
    print str(e)

response = mgmt_client.assume_role( RoleArn="arn:aws:iam::660369111642:role/ListOrganizations",
                                        RoleSessionName="mgmt_session",
                                        DurationSeconds=900)
print response

try:
    master_client = boto3.client('organizations',
                                        aws_access_key_id=response['Credentials']['AccessKeyId'],
                                        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                                        aws_session_token=response['Credentials']['SessionToken'] )

except Exception, e:
    print str(e)

print master_client.list_accounts()

#import pprint
#pp = pprint.PrettyPrinter(indent=4)

# there wasn't a paginator yet so I used this poor man's paginator
# TODO: once organizations has paginators use those.
#accounts = master_client.list_accounts()

#while "NextToken" in accounts.keys():
#    next_accounts=master_client.list_accounts(NextToken=accounts['NextToken'])
#    for account in accounts['Accounts']:
 #       next_accounts['Accounts'].append(account)
#    accounts = next_accounts

#for account in accounts["Accounts"]:
#PaginationConfig={'MaxItems' : 2,'PageSize' : 2, 'StartingToken' : 'string'}
paginator = master_client.get_paginator('list_accounts')
response_iter = paginator.paginate()
count=0
for page in response_iter:
    for account in page['Accounts']:
       # print account['Id']
        count = count +1
print count

bucket_policy = s3.get_bucket_policy(Bucket=s3bucket)
#s3policy = bucket_policy.load()
print bucket_policy['Policy']

