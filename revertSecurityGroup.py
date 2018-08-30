from __future__ import print_function
import json
import urllib
import boto3
import datetime
import os
import logging
from urllib2 import Request, urlopen, URLError, HTTPError
print('Loading function')
SLACK_CHANNEL = os.environ['slackChannel']
MONITORING_HOOK_URL = os.environ['monitoringHookUrl']
APPROVAL_HOOK_URL = os.environ['approvalHookUrl']
ACCOUNT_B_NUMBER = os.environ['accountBNumber']
ACCOUNT_B_NAME = os.environ['accountBName']
ACCOUNT_A_MAIN_REGION = os.environ['accountAMainRegion']
ACCOUNT_A_NUMBER = os.environ['accountANumber']

def icmptype(fromPort,toPort):
	if fromPort == 0:
		type = "Echo Reply"
	elif fromPort == 3:
		if toPort == -1:
			type = "Destination Unreachable (All)"
		elif toPort == 0:
			type = "Destination Unreachable (destination network unreachable)"
		elif toPort == 1:
			type = "Destination Unreachable (destination host unreachable)"
		elif toPort == 2:
			type = "Destination Unreachable (destination protocol unreachable)"
		elif toPort == 3:
			type = "Destination Unreachable (destination port unreachable)"
		elif toPort == 4:
			type = "Destination Unreachable (fragmentation required, and DF flag set)"
		elif toPort == 5:
			type = "Destination Unreachable (source route failed)"
		elif toPort == 6:
			type = "Destination Unreachable (destination network unknown)"
		elif toPort == 7:
			type = "Destination Unreachable (destination host unknown)"
		elif toPort == 8:
			type = "Destination Unreachable (source host isolated)"
		elif toPort == 9:
			type = "Destination Unreachable (network administratively prohibited)"
		elif toPort == 10:
			type = "Destination Unreachable (host administratively prohibited)"
		elif toPort == 11:
			type = "Destination Unreachable (network unreachable for TOS)"
		elif toPort == 12:
			type = "Destination Unreachable (host unreachable for TOS)"
		elif toPort == 13:
			type = "Destination Unreachable (communication administratively prohibited)"
		else:
			type = "Destination Unreachable"
	elif fromPort == 4:
		type = "Source Quench"
	elif fromPort == 5:
		if toPort == -1:
			type = "Redirect Message (All)"
		elif toPort == 0:
			type = "Redirect Message (redirect datagram for the network)"
		elif toPort == 1:
			type = "Redirect Message (redirect datagram for the host)"
		elif toPort == 2:
			type = "Redirect Message (redirect datagram for the TOS & network)"
		elif toPort == 3:
			type = "Redirect Message (redirect datagram for the TOS & host)"
		else:
			type = "Redirect Message"
	elif fromPort == 6:
		type = "Alternate Host Address"
	elif fromPort == 8:
		type = "Echo Request"
	elif fromPort == 9:
		type = "Router Advertisement"
	elif fromPort == 10:
		type = "Router Solicitation"
	elif fromPort == 11:
		if toPort == -1:
			type = "Time Exceeded (All)"
		elif toPort == 0:
			type = "Time Exceeded (TTL expired transit)"
		elif toPort == 1:
			type = "Time Exceeded (fragmentation reasembly time exceeded)"
		else:
			type = "Time Exceeded"
	elif fromPort == 12:
		if toPort == -1:
			type = "Parameter Problem: Bad IP header (All)"
		elif toPort == 0:
			type = "Parameter Problem: Bad IP header (pointer indicates the error)"
		elif toPort == 1:
			type = "Parameter Problem: Bad IP header (missing a required option)"
		elif toPort == 2:
			type = "Parameter Problem: Bad IP header (bad length)"
		else:
			type = "Parameter Problem: Bad IP header"
	elif fromPort == 13:
		type = "Timestamp"
	elif fromPort == 14:
		type = "Timestamp Reply"
	elif fromPort == 15:
		type = "Information Request"
	elif fromPort == 16:
		type = "Information Reply"
	elif fromPort == 17:
		type = "Address Mask Request"
	elif fromPort == 18:
		type = "Address Mask Reply"
	elif fromPort == 30:
		type = "Traceroute"
	elif fromPort == 31:
		type = "Datagram Conversion Error"
	elif fromPort == 32:
		type = "Mobile Host Redirect"
	elif fromPort == 33:
		type = "Where Are You"
	elif fromPort == 34:
		type = "Here I Am"
	elif fromPort == 35:
		type = "Mobile Registration Request"
	elif fromPort == 36:
		type = "Mobile Registration Reply"
	elif fromPort == 37:
		type = "Domain Name Request"
	elif fromPort == 38:
		type = "Domain Name Reply"
	elif fromPort == 39:
		type = "SKIP Algorithm Discovery Protocol"
	elif fromPort == 40:
		type = "Photuris, Security Failures"
	elif fromPort == -1:
		type = "All"
	else:
		type = "Unknown"
	return type
	
def json_builder(item,field1_input,field1_output,field2_input,field2_output):
	hasAddDescription = True
	IpRanges=[]
	protocol=str(item["ipProtocol"])
	for ipranges in item[field1_input]["items"]:
		description = ""
		if "description" in ipranges:
			IpRanges.append({field2_output: str(ipranges[field2_input]), "Description": str(ipranges["description"])})
			description = str(ipranges["description"])
		else:
			IpRanges.append({field2_output: str(ipranges[field2_input])})
		if field1_input == "groups":
			ec2 = boto3.client('ec2')
			secGroupDetails = ec2.describe_security_groups(
				GroupIds=[
					str(ipranges[field2_input]),
				]
			)
			groupName = secGroupDetails["SecurityGroups"][0]["GroupName"]
			source = str(ipranges[field2_input]) + " (" + groupName + ")"
		else:
			source = str(ipranges[field2_input])
		if description == "":
			hasAddDescription = False
	if protocol == "-1":
		if description == "":
			attachment={ "fields": [ { "title": "Protocol", "value": "All Traffic", "short": True }, { "title": "Source", "value": source, "short": True } ], "color": "#f98c3e" }
		else:
			attachment={ "fields": [ { "title": "Protocol", "value": "All Traffic", "short": True }, { "title": "Source", "value": source, "short": True }, { "title": "Description", "value": description, "short": True } ], "color": "#f98c3e" }
		permissions={"IpProtocol": protocol, field1_output: IpRanges}
	elif protocol == "icmp":
		permissions={"IpProtocol": protocol, "ToPort": item["toPort"], "FromPort": item["fromPort"], field1_output: IpRanges}
		if description == "":
			attachment={ "fields": [ { "title": "Protocol", "value": str(protocol), "short": True }, { "title": "Type", "value": icmptype(item["fromPort"],item["toPort"]), "short": True }, { "title": "Source", "value": source, "short": True } ], "color": "#f98c3e" }
		else:
			attachment={ "fields": [ { "title": "Protocol", "value": str(protocol), "short": True }, { "title": "Type", "value": icmptype(item["fromPort"],item["toPort"]), "short": True }, { "title": "Source", "value": source, "short": True }, { "title": "Description", "value": description, "short": True } ], "color": "#f98c3e" }
	else:
		permissions={"IpProtocol": protocol, "ToPort": item["toPort"], "FromPort": item["fromPort"], field1_output: IpRanges}
		if item["fromPort"] == item["toPort"]:
			portRange = str(item["fromPort"])
		else:
			portRange = str(item["fromPort"]) + ' - ' + str(item["toPort"])
		if portRange == "-1":
			if description == "":
				attachment={ "fields": [ { "title": "Protocol", "value": str(protocol), "short": True }, { "title": "Source", "value": source, "short": True } ], "color": "#f98c3e" }
			else:
				attachment={ "fields": [ { "title": "Protocol", "value": str(protocol), "short": True }, { "title": "Source", "value": source, "short": True }, { "title": "Description", "value": description, "short": True } ], "color": "#f98c3e" }
		else:
			if description == "":
				attachment={ "fields": [ { "title": "Protocol", "value": str(protocol), "short": True }, { "title": "Port", "value": portRange, "short": True }, { "title": "Source", "value": source, "short": True } ], "color": "#f98c3e" }
			else:
				attachment={ "fields": [ { "title": "Protocol", "value": str(protocol), "short": True }, { "title": "Port", "value": portRange, "short": True }, { "title": "Source", "value": source, "short": True }, { "title": "Description", "value": description, "short": True } ], "color": "#f98c3e" }
	response = []
	response.append(attachment)
	response.append(permissions)
	response.append({"hasAddDescription": hasAddDescription})
	return response
		
def lambda_handler(event, context):
	hasAddDescription = True
	print("An unauthorized security group change was detected and will be remediated. The event details are:")
	print("----------------------")
	print("Received event: " + json.dumps(event, indent=5))
	print("----------------------")
	# check if reequest was made in the last 5 minutes
	eventTime=event["time"]
	timeBefore = (datetime.datetime.now() - datetime.timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ')
	print("eventTime = " + eventTime)
	print("timeBefore = " + timeBefore)
	if eventTime > timeBefore:
		print("made in the last 5 minutes")
	else:
		return "made more than 5 minutes ago"
	adminUsers = [
		"arn:aws:iam::" + ACCOUNT_B_NUMBER + ":user/admin*",
		"arn:aws:iam::" + ACCOUNT_B_NUMBER + ":user/Admin*"
	]
	isAdmin = False
	for item in adminUsers:
		if item == event["detail"]["userIdentity"]["arn"]:
			isAdmin = True
			break
	if isAdmin == False:
		print("Someone other than the admin account tried to make the change")
		if event["detail"]["eventName"] == "AuthorizeSecurityGroupIngress":
			print("RULE ADD DETECTED")
		else:
			print("RULE REMOVE DETECTED")
	else:
		print("Change was made by admin")
		return "Change was made by admin"
	ec2 = boto3.client('ec2')
	secGroupDetails = ec2.describe_security_groups(
		GroupIds=[
			event["detail"]["requestParameters"]["groupId"],
		]
	)
	groupName = secGroupDetails["SecurityGroups"][0]["GroupName"]
	if "ipPermissions" in event["detail"]["requestParameters"]:
		group = event["detail"]["requestParameters"]["groupId"]
		permissions = []
		attachment = []
		account = str(event["account"])
		for item in event["detail"]["requestParameters"]["ipPermissions"]["items"]:
			description = ""
			if item["ipRanges"] != {}:
				field1_input = "ipRanges"
				field1_output = "IpRanges"
				field2_input = "cidrIp"
				field2_output = "CidrIp"
			if item["ipv6Ranges"] != {}:
				field1_input = "ipv6Ranges"
				field1_output = "Ipv6Ranges"
				field2_input = "cidrIpv6"
				field2_output = "CidrIpv6"
			if item["prefixListIds"] != {}:
				field1_input = "prefixListIds"
				field1_output = "PrefixListIds"
				field2_input = "prefixListId"
				field2_output = "PrefixListId"
			if item["groups"] !={}:
				field1_input = "groups"
				field1_output = "UserIdGroupPairs"
				field2_input = "groupId"
				field2_output = "GroupId"
			response=json_builder(item,field1_input,field1_output,field2_input,field2_output)
			attachment.append(response[0])
			permissions.append(response[1])
			if response[2]["hasAddDescription"] == False:
				hasAddDescription = False
	else:
		print("An ingress rule change was detected, but not in the expected format. You should debug and find out why. Probably an EC2-Classic call.") 
		return "An ingress rule change was detected, but not in the expected format. You should debug and find out why. Probably an EC2-Classic call."  
	if account == ACCOUNT_B_NUMBER:
		account = ACCOUNT_B_NAME
	print("----------------------")
	print("Permission: " + json.dumps(permissions, indent=5))
	print("----------------------")
	print(hasAddDescription)
	if event["detail"]["eventName"] == "AuthorizeSecurityGroupIngress":
		remove_rule = ec2.revoke_security_group_ingress(
		GroupId=group,
		IpPermissions=permissions
		)
		action = 'add'
		button_label = "Approve Add"
	else:
		add_rule = ec2.authorize_security_group_ingress(
		GroupId=group,
		IpPermissions=permissions
		)
		action = 'remove'
		button_label = "Approve Remove"
		hasAddDescription = True
	if hasAddDescription:
		monitoring_attachment = list(attachment)
		monitoring_attachment.append({'text': ':stopwatch: Pending Approval', "color": "#f98c3e" })
		monitoring_message = {
			'text': 'Request ID: ' + str(event["detail"]["requestID"]) + '\n*' + str(event["detail"]["userIdentity"]["userName"]) + '* requested to *' + action + '* inbound rule to *' + str(group) + ' (' + str(groupName) + ')* in *' + account + '*',
			"attachments": monitoring_attachment
		}
		attachment.append({"fallback": "You were unable to choose", "callback_id": str(event["detail"]["requestID"]), "color": "#f98c3e", "attachment_type": "default", "actions": [ { "name": "game", "text": button_label, "type": "button", "value": "approve", "style": "primary" }, { "name": "game", "text": "Deny", "type": "button", "value": "deny", "style": "danger" } ] })
		slack_message = {
			'text': 'Request ID: ' + str(event["detail"]["requestID"]) + '\n*' + str(event["detail"]["userIdentity"]["userName"]) + '* requested to *' + action + '* inbound rule to *' + str(group) + ' (' + str(groupName) + ')* in *' + account + '*',
			"attachments": attachment
		}
	else:
		color = "#f71818"
		new_attachment = []
		for original_attachment_item in attachment:
			attachment_item = {
				"color": color,
				"fields": original_attachment_item["fields"]
			}
			new_attachment.append(attachment_item)
		new_attachment.append({'text': ':x: Auto denied: Each rule must have description', "color": "#f71818" })
		slack_message = {
			'text': 'Request ID: ' + str(event["detail"]["requestID"]) + '\n*' + str(event["detail"]["userIdentity"]["userName"]) + '* requested to *' + action + '* inbound rule to *' + str(group) + ' (' + str(groupName) + ')* in *' + account + '*',
			"attachments": new_attachment
		}
		monitoring_message = slack_message
	req2 = Request(APPROVAL_HOOK_URL, json.dumps(slack_message))
	print(json.dumps(slack_message))
	try:
		response2 = urlopen(req2)
		response2.read()
		print("Message posted to approval channel")
	except HTTPError as e:
		print("Request failed: " + e.code + " " + e.reason)
	except URLError as e:
		print("Server connection failed: " + e.reason)
	req = Request(MONITORING_HOOK_URL, json.dumps(monitoring_message))
	try:
		response = urlopen(req)
		response.read()
		print("Message posted to monitoring channel")
	except HTTPError as e:
		print("Request failed: " + e.code + " " + e.reason)
	except URLError as e:
		print("Server connection failed " + e.reason)
	if hasAddDescription:
		sns = boto3.client('sns', region_name='ap-southeast-1')
		sns.publish(
			TopicArn="arn:aws:sns:" + ACCOUNT_A_MAIN_REGION + ":" + ACCOUNT_A_NUMBER + ":securityGroupChange",
			Subject=groupName,
			Message=json.dumps(event)
		)
	print(permissions)
	return 'success'