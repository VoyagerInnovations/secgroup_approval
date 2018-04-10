from __future__ import print_function

import json
import urllib
import urlparse
import boto3
import os
import time
from urllib2 import Request, urlopen, URLError, HTTPError

MONITORING_HOOK_URL = os.environ['monitoringHookUrl']

def lambda_handler(receivedEvent, context):
	print("Loading function...")
	for item in receivedEvent["Records"]:
		event = json.loads(item["Sns"]["Message"])
		groupName = item["Sns"]["Subject"]
		payload = json.loads(event['payload'])
		print("----------------------")
		print("Received event: " + json.dumps(event, indent=5))
		print("----------------------")
		ec2 = boto3.client('ec2')
		original_attachements=payload["original_message"]["attachments"]
		original_attachements.pop()
		attachment = []
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
		print("Permissions: " + json.dumps(permissions, indent=5))
		requestedBy = str(item['requestedBy'])
		requestType = str(item['requestType'])
		account = item['account']
		color = "#f71818"
		action = ':x: Denied'
		try:
			for original_attachment_item in original_attachements:
				attachment_item = {
					"color": color,
					"fields": original_attachment_item["fields"]
				}
				attachment.append(attachment_item)
		except Exception as e:
			slack_message = {
				'text': 'Error processing request id ' + reqid + '\n' + str(e)
			}
			return slack_message
		except:
			slack_message = {
				'text': 'Error processing request id ' + reqid
			}
			return slack_message   
		attachment.append({'text': action + ' by <@' + payload['user']['id'] + '>', "color": "#f71818" })
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