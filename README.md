<a href="https://work.amit.cloud"><img src="https://s3-ap-south-1.amazonaws.com/amitcloud/work.amit.cloud/wp-content/uploads/2019/04/19101016/logo.svg?sanitize=true" title="amit.cloud" alt="Amit Sharma" height="50"></a>

Checkout my profile and other projects at [amit.cloud](http://work.amit.cloud)

# Notify IAM Updates
This script notifies updates in IAM Policies and Users as per incoming events.

The script works with Cloudwatch rule to monitor Events related to IAM updates.

This setup works only in North Virginia Region (us-east-1).

### Usage (In N. Virginia Region):
1. Create a Lambda function with all three scripts.
2. Configure lambda handler to point to `main.lambda_handler()`
3. Create a new Cloudwatch rule for IAM service and all event types. 
4. For Trigger, add the lamdba create in first two steps. 

### Events Supported (For both Allowed and Denied events):
- CreateUser
- DeleteUser
- AttachUserPolicy
- DetachUserPolicy
- CreatePolicy
- DeletePolicy
- CreatePolicyVersion

### Other Details
- Python Version = 3.7.2
- Boto3 Version = 1.9.188