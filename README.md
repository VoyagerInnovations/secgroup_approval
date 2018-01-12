# AWS Security Group Approval via Slack
The ability to revert unapproved security group (firewall) inbound changes in Amazon Web Services and subsequently approve or disapprove the request via Slack API and interactive buttons.

## Requesting to Add/Update/Delete Rules
1. Open the Amazon EC2 console at https://console.aws.amazon.com/ec2/.
2. In the navigation pane, choose Security Groups.
3. Select the security group to update, and choose Inbound Rules to add/update/delete rules for inbound traffic.
4. Choose Edit. Modify the rule entry as required and choose Save.

![Add Rule](images/add_rule.png)

5. Within a few seconds, a request will be sent via Slack API to the approvers for proper action and the security group will be reverted back to its original state. The request will also be posted to the slack monitoring channel.

![Monitoring Channel Pending](images/add_rule_monitoring.png)

6. Once approved/denied, another message will be posted to the slack monitoring channel.

![Monitoring Channel Approved](images/add_rule_monitoring_approved.png)

## Approving/Denying Requests
1. Once the change to a security group is detected, a message will be sent to the slack approving channel for proper action. Message information includes a unique request id, requester, add/remove action, group ID, AWS account, and inbound rules.

![Approval Channel Pending](images/add_rule_approval.png)

2. Simply click the approve button to apply the rule change or click the deny button to deny the request.

![Approval Channel Denied](images/add_rule_denied.png)

## Limitations
1. It takes a few seconds (around 30 seconds) for Cloudwatch to trigger the initial Lambda function. There will be a short period where a rule is still subject for reversion by the Lambda function.
2. Rule edits are treated as two separate add and remove requests.

## Back-End
### Receiving Requests

![Receiving Requests Diagram](images/receiving_requests.png)

Any rule add/edit cloudwatch event in AWS account B will trigger a Lambda function that reverts the security group to its original state, publish to an SNS topic in AWS account A, and send a message to Slack. The SNS topic in AWS account A will trigger a Lambda function that stores the request in DynamoDB.

### Approving/Denying Requests

![Approving/Denying Requests Diagram](images/approving_denying_requests.png)

Once an approver acts on a request by pressing a button, Slack sends an HTTP to an API Gateway in AWS Account A. The API Gateway triggers a Lambda function that would update DynamoDB. If the approver denies the request, the Lambda function would just tag the request as ‘denied’. Otherwise, if the approver approves the request, the Lambda function would tag the request as ‘approved’ and publish to an SNS topic in AWS Account B. The SNS topic in AWS account B will trigger a Lambda function that applies the requested rule changes to the specified security group. If an error occurs (e.g. duplicate rule, non existing rule), the request would be tagged as error.