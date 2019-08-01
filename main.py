import json
import notify
import analyze


def extract_core_details(event):
    event_details = {}
    event_name = event["detail"]["eventName"]
    event_owner = event["detail"]["userIdentity"]["userName"]
    t_stamp = event["detail"]["eventTime"]
    try:
        error_code = event["detail"]["errorCode"]
        error_message = event["detail"]["errorMessage"]
    except KeyError:
        error_code = None
        error_message = None
    if error_code:
        subject = error_message.split(" ")[-1]
    else:
        try:
            subject = event["detail"]["requestParameters"]["userName"]
        except KeyError:
            subject = event["detail"]["requestParameters"]

    event_details["eventName"] = event_name
    event_details["eventOwner"] = event_owner
    event_details["timestamp"] = t_stamp
    event_details["errorCode"] = error_code
    event_details["errorMessage"] = error_message
    event_details["subject"] = subject

    return event_details


def lambda_handler(event, context):
    event_details = extract_core_details(event)
    analyze.event(event_details, event)

    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }
