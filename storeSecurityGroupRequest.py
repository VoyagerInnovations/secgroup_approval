from __future__ import print_function
import json
import urllib
import boto3
import datetime
import os
import logging
from datetime import datetime
from urllib2 import Request, urlopen, URLError, HTTPError
print('Loading function')
ec2 = boto3.client('ec2')

def json_builder(item,field1_input,field1_output,field2_input,field2_output):
	IpRanges=[]
	protocol=str(item["ipProtocol"])
	for ipranges in item[field1_input]["items"]:
		if "description" in ipranges:
			IpRanges.append({field2_output: str(ipranges[field2_input]),"Description": str(ipranges["description"])})
		else:
			IpRanges.append({field2_output: str(ipranges[field2_input])})
	if protocol == "-1":
		permissions={"IpProtocol": protocol, field1_output: IpRanges}
	else:
		permissions={"IpProtocol": protocol, "ToPort": item["toPort"], "FromPort": item["fromPort"], field1_output: IpRanges}
	return permissions

def lambda_handler(receivedEvent, context):
	print("----------------------")
	print("Received event: " + json.dumps(receivedEvent, indent=5))
	print("----------------------")
	print("Someone other than the admin account tried to make the change")
	for item in receivedEvent["Records"]:
		event = json.loads(item["Sns"]["Message"])
		groupName = item["Sns"]["Subject"]
		if event["detail"]["eventName"] == "AuthorizeSecurityGroupIngress":
			requestType = "add"
			print("RULE ADD DETECTED")
		else:
			requestType = "remove"
			print("RULE REMOVE DETECTED")
		if "ipPermissions" in event["detail"]["requestParameters"]:
			group = event["detail"]["requestParameters"]["groupId"]
			attachment = []
			permissions = []
			region = str(event["region"])
			account = str(event["account"])
			dynamodb = boto3.client('dynamodb')
			for item in event["detail"]["requestParameters"]["ipPermissions"]["items"]:
				protocol=str(item["ipProtocol"])
				if item["ipRanges"] != {}:
					field1_input = "ipRanges"
					field1_output = "IpRanges"
					field2_input = "cidrIp"
					field2_output = "CidrIp"
					permissions.append(json_builder(item,field1_input,field1_output,field2_input,field2_output))
				if item["ipv6Ranges"] != {}:
					field1_input = "ipv6Ranges"
					field1_output = "Ipv6Ranges"
					field2_input = "cidrIpv6"
					field2_output = "CidrIpv6"
					permissions.append(json_builder(item,field1_input,field1_output,field2_input,field2_output))
				if item["prefixListIds"] != {}:
					field1_input = "prefixListIds"
					field1_output = "PrefixListIds"
					field2_input = "prefixListId"
					field2_output = "PrefixListId"
					permissions.append(json_builder(item,field1_input,field1_output,field2_input,field2_output))
				if item["groups"] !={}:
					field1_input = "groups"
					field1_output = "UserIdGroupPairs"
					field2_input = "groupId"
					field2_output = "GroupId"
					permissions.append(json_builder(item,field1_input,field1_output,field2_input,field2_output))
			dynamodb.put_item(TableName="securityGroupRequests", Item={"requestId": {'S': str(event["detail"]["requestID"])}, "SecGroup": {'S': str(group)}, "Permissions": {'S': json.dumps(permissions)}, "current_status": {'S': 'pending'}, "requestedBy": {'S': str(event["detail"]["userIdentity"]["userName"])}, "account": {'S': account}, "region": {'S': region}, "requestType": {'S': requestType}, "groupName": {'S': str(groupName)}, "decidedBy": {'S': 'pending'}, "decidedOn": {'S': 'pending'}, "requestTime": {'S': str(datetime.now().strftime('%Y%m%d%H%M%S'))}})
			print("Permissions: " + json.dumps(permissions, indent=5))
		else:
			print("An ingress rule change was detected, but not in the expected format. You should debug and find out why. Probably an EC2-Classic call.")
		return 'success'
