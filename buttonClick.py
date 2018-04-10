from __future__ import print_function

import json
import urllib
import urlparse
import boto3
import os
import time
import datetime
from urllib2 import Request, urlopen, URLError, HTTPError

ACCOUNT_A_MAIN_REGION = os.environ['accountAMainRegion']
ACCOUNT_A_NUMBER = os.environ['accountANumber']

def lambda_handler(event, context):
	print("----------------------")
	print("Received event: " + json.dumps(event, indent=5))
	print("----------------------")
	try:
		payload = json.loads(urlparse.parse_qs(event['body'])['payload'][0])
	except:
		return ''
	token = payload['token']
	expected_token = os.environ['expectedToken']
	if token != expected_token:
		print("Request token (" + token + ") does not match expected")
		return respond(Exception('Invalid request token'))
	print("----------------------")
	print("Received payload: " + json.dumps(payload, indent=5))
	print("----------------------")
	ec2 = boto3.client('ec2')
	dynamodb = boto3.resource('dynamodb')
	attachment = []
	table = dynamodb.Table('securityGroupRequests')
	reqid = payload['callback_id']
	print(reqid)
	response = table.get_item(
		Key={
			'requestId': reqid
		}
	)
	item = response['Item']
	permissions = item['Permissions']
	group = item['SecGroup']
	requestedBy = str(item['requestedBy'])
	requestType = str(item['requestType'])
	decidedBy = str(item['decidedBy'])
	groupName = item['groupName']
	account = item['account']
	region = item['region']
	SNS_TOPIC = "arn:aws:sns:" + region + ":" + account + ":applySecurityGroupChange"
	sns = boto3.client("sns", region_name=region)
	original_attachements=payload["original_message"]["attachments"]
	original_attachements.pop()
	attachment = []
	if str(item['current_status']) == "pending":
		if 'approve' == payload['actions'][0]['value']:
			try:
				sns.publish(
					TopicArn=SNS_TOPIC,
					Subject=str(groupName),
					Message=json.dumps({"response": json.dumps(response), "payload": urlparse.parse_qs(event['body'])['payload'][0], "IpPermissions": permissions, "GroupId": group, "action": requestType, "responseUrl": payload['response_url']}),
				)
				table.update_item(
					Key={
						'requestId': reqid
					},
					UpdateExpression='SET current_status = :val1',
					ExpressionAttributeValues={
						':val1': 'approved'
					}
				)
				table.update_item(
					Key={
						'requestId': reqid
					},
					UpdateExpression='SET decidedBy = :val1',
					ExpressionAttributeValues={
						':val1': payload['user']['name']
					}
				)
				table.update_item(
					Key={
						'requestId': reqid
					},
					UpdateExpression='SET decidedOn = :val1',
					ExpressionAttributeValues={
						':val1': str(datetime.datetime.now().strftime('%Y%m%d%H%M%S'))
					}
				)
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
		else:
			sns2 = boto3.client("sns", region_name="ap-southeast-1")
			try:
				sns2.publish(
					TopicArn="arn:aws:sns:" + ACCOUNT_A_MAIN_REGION + ":" + ACCOUNT_A_NUMBER + ":denySecurityGroupChange",
					Subject=str(groupName),
					Message=json.dumps({"response": json.dumps(response), "payload": urlparse.parse_qs(event['body'])['payload'][0], "IpPermissions": permissions, "GroupId": group, "action": requestType, "responseUrl": payload['response_url']}),
				)
				table.update_item(
					Key={
						'requestId': reqid
					},
					UpdateExpression='SET current_status = :val1',
					ExpressionAttributeValues={
						':val1': 'denied'
					}
				)
				table.update_item(
					Key={
						'requestId': reqid
					},
					UpdateExpression='SET decidedBy = :val1',
					ExpressionAttributeValues={
						':val1': payload['user']['name']
					}
				)
				table.update_item(
					Key={
						'requestId': reqid
					},
					UpdateExpression='SET decidedOn = :val1',
					ExpressionAttributeValues={
						':val1': str(datetime.datetime.now().strftime('%Y%m%d%H%M%S'))
					}
				)
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
		color = "#f98c3e"
		last_line = 'Processing...'
	elif str(item['current_status']) == "denied":
		color = "#f71818"
		last_line = 'Already denied by <@' + decidedBy + '>'
	elif str(item['current_status']) == "approved":
		color = "#29a52d"
		last_line = 'Already approved by <@' + decidedBy + '>'
	for original_attachment_item in original_attachements:
		attachment_item = {
			"color": color,
			"fields": original_attachment_item["fields"]
		}
		attachment.append(attachment_item)
	attachment.append({'text': last_line, "color": color })
	message = {
		"text": payload["original_message"]["text"],
		"attachments": attachment
	}
	print("----------------------")
	print("Message to be sent: " + json.dumps(message, indent=5))
	print("----------------------")
	return message