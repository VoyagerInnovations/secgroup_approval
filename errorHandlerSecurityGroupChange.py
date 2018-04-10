from __future__ import print_function

import json
import urllib
import urlparse
import boto3
import os
import time
from urllib2 import Request, urlopen, URLError, HTTPError

MONITORING_HOOK_URL = os.environ['monitoringHookUrl']

def lambda_handler(errorEvent, context):
	print("Loading function...")
	print("----------------------")
	print("Received event: " + json.dumps(errorEvent, indent=5))
	receivedEvent=json.loads(errorEvent["Records"][0]["Sns"]["Message"])[0]
	error=json.loads(errorEvent["Records"][0]["Sns"]["Message"])[1]["errormessage"]
	for item in receivedEvent["Records"]:
		event = json.loads(item["Sns"]["Message"])
		groupName = item["Sns"]["Subject"]
		payload = json.loads(event['payload'])
		token = payload['token']
		print("----------------------")
		print("Received event: " + json.dumps(event, indent=5))
		print("----------------------")
		ec2 = boto3.client('ec2')
		dynamodb = boto3.resource('dynamodb')
		table = dynamodb.Table('securityGroupRequests')
		reqid = payload['callback_id']
		table.update_item(
			Key={
				'requestId': reqid
			},
			UpdateExpression='SET current_status = :val1',
			ExpressionAttributeValues={
				':val1': error
			}
		)
		original_attachements=payload["original_message"]["attachments"]
		original_attachements.pop()
		attachment = []
		action = ':scream: ' + error
		color = "#f71818"
		for original_attachment_item in original_attachements:
			attachment_item = {
				"color": color,
				"fields": original_attachment_item["fields"]
			}
			attachment.append(attachment_item)
		attachment.append({'text': action, "color": "#f71818" })
		attachment.append({'text': 'by <@' + payload['user']['id'] + '>', "color": "#f71818" })
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
	print("message: " + json.dumps(message, indent=5))
	print("----------------------")
	return message