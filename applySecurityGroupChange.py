from __future__ import print_function

import json
import urllib
import urlparse
import boto3
import os
import time
from urllib2 import Request, urlopen, URLError, HTTPError

MONITORING_HOOK_URL = os.environ['monitoringHookUrl']
ACCOUNT_A_MAIN_REGION = os.environ['accountAMainRegion']
ACCOUNT_A_NUMBER = os.environ['accountANumber']

def error_handler(receivedEvent,subject):
	sns = boto3.client('sns')
	SNS_TOPIC = "arn:aws:sns:" + ACCOUNT_A_MAIN_REGION + ":" + ACCOUNT_A_NUMBER + ":errorHandlerSecurityGroupChange"
	print(str(subject))
	message=[]
	message.append(receivedEvent)
	message.append({ "errormessage": str(subject)})
	sns.publish(
		TopicArn=SNS_TOPIC,
		Subject="Error",
		Message=json.dumps(message),
	)
	return 0

def lambda_handler(receivedEvent, context):
	print("Loading function...")
	print("----------------------")
	print("receivedEvent: " + json.dumps(receivedEvent, indent=5))
	for item in receivedEvent["Records"]:
		event = json.loads(item["Sns"]["Message"])
		groupName = item["Sns"]["Subject"]
		payload = json.loads(event['payload'])
		print("----------------------")
		print("event: " + json.dumps(event, indent=5))
		print("----------------------")
		ec2 = boto3.client('ec2')
		original_attachements=payload["original_message"]["attachments"]
		original_attachements.pop()
		attachment = []
		color = "#29a52d"
		reqid = payload['callback_id']
		response = json.loads(event['response'])
		item = response['Item']
		try:
			permissions = item['Permissions']
		except:
			print("perm")
		try:
			group = item['SecGroup']
		except:
			print("sec")
		requestedBy = str(item['requestedBy'])
		requestType = str(item['requestType'])
		account = item['account']
		action = ':white_check_mark: Approved'
		try:
			if requestType == 'add':
				add_rule = ec2.authorize_security_group_ingress(
				GroupId=group,
				IpPermissions=json.loads(permissions)
				)
			else:
				revoke_rule = ec2.revoke_security_group_ingress(
				GroupId=group,
				IpPermissions=json.loads(permissions)
				)
			for original_attachment_item in original_attachements:
				attachment_item = {
					"color": color,
					"fields": original_attachment_item["fields"]
				}
				attachment.append(attachment_item)
		except Exception as e:
			slack_message=error_handler(receivedEvent, str(e))
			return slack_message
		except:
			send=""
			slack_message=error_handler(receivedEvent, str(send))
			return slack_message 
		attachment.append({'text': action + ' by <@' + payload['user']['id'] + '>', "color": "#29a52d" })
		message = {
			"text": payload["original_message"]["text"],
			"attachments": attachment
		}
		print (payload['response_url'])
		req = Request(MONITORING_HOOK_URL, json.dumps(message))
		try:
			response = urlopen(req)
			response.read()
			print("Message posted to monitoring channel")
		except HTTPError as e:
			print("Request failed: %d %s", e.code, e.reason)
		except URLError as e:
			print("Server connection failed: %s", e.reason)
		req2 = Request(payload['response_url'], json.dumps(message))
		try:
			response2 = urlopen(req2)
			response2.read()
			print("Message posted to approvers channel")
		except HTTPError as e:
			print("Request failed: %d %s", e.code, e.reason)
		except URLError as e:
			print("Server connection failed: %s", e.reason)
	return message