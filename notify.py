import boto3
import os

from base64 import b64decode

ENCRYPTED = os.environ['topic_arn']
DECRYPTED = boto3.client('kms').decrypt(CiphertextBlob=b64decode(ENCRYPTED))['Plaintext'].decode("utf-8")


def publish_to_sns(sub, msg):
    topic_arn = str(DECRYPTED)
    sns = boto3.client("sns")
    response = sns.publish(
        TopicArn=topic_arn,
        Message=msg,
        Subject=sub
    )


def notify_createUser_allowed(subject="N/A", owner="N/A", t_event="N/A"):
    sub = "IAM: New User Created"
    msg = """
        A new user is created:
        ____________________________________________________________________________________________________________________________________
        User Name         :    {sub}
        Event Owner       :    {e_owner}
        Timestamp          :    {timeofcreation}  
        ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
        """.format(sub=subject, e_owner=owner, timeofcreation=str(t_event))
    print("LOG [CreateUser]: \n" + msg)
    publish_to_sns(sub, msg)


def notify_createUser_denied(subject="N/A", owner="N/A", t_event="N/A", e_code="N/A", e_message="N/A"):
    # if event_name == "CreateUser":
    sub = "IAM: Failed New User Creation"
    msg = """
        New user creation attempt failed:
        ____________________________________________________________________________________________________________________________________
        User Name          :    {sub}
        Event Owner       :    {e_owner}
        Timestamp          :    {timeofcreation}  
        Error Code          :    {error_code}
        Error Message    :    {error_message}
        ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
        """.format(sub=subject, e_owner=owner, timeofcreation=str(t_event), error_code=str(e_code),
                   error_message=e_message)
    print("LOG [CreateUser]: \n" + msg)
    publish_to_sns(sub, msg)


def notify_deleteUser_allowed(subject="N/A", owner="N/A", t_event="N/A"):
    sub = "IAM: User Deleted"
    msg = """
        A user was deleted:
        ____________________________________________________________________________________________________________________________________
        User Name         :    {sub}
        Event Owner       :    {e_owner}
        Timestamp          :    {timeofcreation}  
        ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
        """.format(sub=subject, e_owner=owner, timeofcreation=str(t_event))
    print("LOG [CreateUser]: \n" + msg)
    publish_to_sns(sub, msg)


def notify_deleteUser_denied(subject="N/A", owner="N/A", t_event="N/A", e_code="N/A", e_message="N/A"):
    # if event_name == "CreateUser":
    sub = "IAM: Failed User Deletion"
    msg = """
        User deletion attempt Failed:
        ____________________________________________________________________________________________________________________________________
        User Name         :    {sub}
        Event Owner       :    {e_owner}
        Timestamp          :    {timeofcreation}  
        Error Code          :    {error_code}
        Error Message    :    {error_message}
        ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
        """.format(sub=subject, e_owner=owner, timeofcreation=str(t_event), error_code=str(e_code),
                   error_message=e_message)
    print("LOG [CreateUser]: \n" + msg)
    publish_to_sns(sub, msg)


def notify_AttachUserPolicy_allowed(subject="N/A", owner="N/A", policy_arn="N/A", t_event="N/A"):
    sub = "IAM: Policy Attached to Existing User"
    msg = """
        An existing policy was attached to a user:
        ____________________________________________________________________________________________________________________________________
        User Name         :    {sub}
        Event Owner      :    {e_owner}
        Policy ARN         :    {policy}
        Timestamp         :    {timeofcreation}  
        ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
        """.format(sub=subject, e_owner=owner, policy=policy_arn, timeofcreation=str(t_event))
    print("LOG [CreateUser]: \n" + msg)
    publish_to_sns(sub, msg)


def notify_AttachUserPolicy_denied(subject="N/A", owner="N/A", t_event="N/A", e_code="N/A", e_message="N/A"):
    sub = "IAM: Failed to Attach User Policy"
    msg = """
        Attach User Policy attempt Failed:
        ____________________________________________________________________________________________________________________________________
        User Name         :    {sub}
        Event Owner       :    {e_owner}
        Timestamp          :    {timeofcreation}  
        Error Code          :    {error_code}
        Error Message    :    {error_message}
        ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
        """.format(sub=subject, e_owner=owner, timeofcreation=str(t_event), error_code=str(e_code),
                   error_message=e_message)
    print("LOG [CreateUser]: \n" + msg)
    publish_to_sns(sub, msg)


def notify_DetachUserPolicy_allowed(subject="N/A", owner="N/A", policy_arn="N/A", t_event="N/A"):
    sub = "IAM: Policy Detached from Existing User"
    msg = """
        An existing policy was attached to a user:
        ____________________________________________________________________________________________________________________________________
​        User Name          :    {sub}
        Event Owner      :    {e_owner}
        Policy ARN         :    {policy}
        Timestamp         :    {timeofcreation}  
        ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
        """.format(sub=subject, e_owner=owner, policy=policy_arn, timeofcreation=str(t_event))
    print("LOG [CreateUser]: \n" + msg)
    publish_to_sns(sub, msg)


def notify_DetachUserPolicy_denied(subject="N/A", owner="N/A", t_event="N/A", e_code="N/A", e_message="N/A"):
    sub = "IAM: Failed to Detach User Policy"
    msg = """
        Attach User Policy attempt Failed:
        ____________________________________________________________________________________________________________________________________
​        User Name          :    {sub}
        Event Owner       :    {e_owner}
        Timestamp          :    {timeofcreation}  
        Error Code          :    {error_code}
        Error Message    :    {error_message}​

        ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
        """.format(sub=subject, e_owner=owner, timeofcreation=str(t_event), error_code=str(e_code),
                   error_message=e_message)
    print("LOG [CreateUser]: \n" + msg)
    publish_to_sns(sub, msg)


def notify_CreatePolicy_allowed(owner="N/A", policy_arn="N/A", t_event="N/A", policy_doc="N/A"):
    sub = "IAM: New Policy Created"
    msg = """
        A new policy was created:
        ____________________________________________________________________________________________________________________________________
        Event Owner       :    {e_owner}
        Policy Name        :    {policy}
        Timestamp          :    {timeofcreation}  
        ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
        Policy Document:
        {policy_document}
        ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
        """.format(e_owner=owner, policy=policy_arn, timeofcreation=str(t_event),
                   policy_document=policy_doc)
    print("LOG [CreateUser]: \n" + msg)
    publish_to_sns(sub, msg)


def notify_CreatePolicy_denied(owner="N/A", t_event="N/A", e_code="N/A", e_message="N/A"):
    sub = "IAM: Failed to Create Policy"
    msg = """
        Create Policy attempt Failed:
        ____________________________________________________________________________________________________________________________________
        Event Owner       :    {e_owner}
        Timestamp          :    {timeofcreation}  
        Error Code          :    {error_code}
        Error Message    :    {error_message}
        ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
        """.format(e_owner=owner, timeofcreation=str(t_event), error_code=str(e_code),
                   error_message=e_message)
    print("LOG [CreateUser]: \n" + msg)
    publish_to_sns(sub, msg)


def notify_DeletePolicy_allowed(owner="N/A", policy_arn="N/A", t_event="N/A"):
    sub = "IAM: Policy Deleted"
    msg = """
        A policy was deleted:
        ____________________________________________________________________________________________________________________________________
        Event Owner      :    {e_owner}
        Policy ARN         :    {policy}
        Timestamp         :    {timeofcreation}  
        ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
        """.format(e_owner=owner, policy=policy_arn, timeofcreation=str(t_event))
    print("LOG [CreateUser]: \n" + msg)
    publish_to_sns(sub, msg)


def notify_DeletePolicy_denied(owner="N/A", t_event="N/A", e_code="N/A", e_message="N/A"):
    sub = "IAM: Failed to Delete Policy"
    msg = """
        Delete Policy attempt Failed:
        ____________________________________________________________________________________________________________________________________
        Event Owner       :    {e_owner}
        Timestamp          :    {timeofcreation}  
        Error Code          :    {error_code}
        Error Message    :    {error_message}
        ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
        """.format(e_owner=owner, timeofcreation=str(t_event), error_code=str(e_code),
                   error_message=e_message)
    print("LOG [CreateUser]: \n" + msg)
    publish_to_sns(sub, msg)


def notify_CreatePolicyVersion_allowed(owner="N/A", policy_arn="N/A", t_event="N/A", policy_doc="N/A"):
    sub = "IAM: Policy Updated"
    msg = """
        A policy was updated:
        ____________________________________________________________________________________________________________________________________
        Event Owner       :    {e_owner}
        Policy ARN         :    {policy}
        Timestamp          :    {timeofcreation}  
        ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
        Updated Policy Document:
        {policy_document}
        ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
        """.format(e_owner=owner, policy=policy_arn, timeofcreation=str(t_event),
                   policy_document=policy_doc)
    print("LOG [CreateUser]: \n" + msg)
    publish_to_sns(sub, msg)


def notify_CreatePolicyVersion_denied(subject="N/A", owner="N/A", t_event="N/A", e_code="N/A", policy_name="N/A",
                                      e_message="N/A"):
    sub = "IAM: Failed to Update Policy"
    msg = """
        Update Policy attempt Failed:
        ____________________________________________________________________________________________________________________________________
        Policy                  :    {sub}
        Event Owner       :    {e_owner}
        Timestamp          :    {timeofcreation}  
        Error Code          :    {error_code}
        Error Message    :    {error_message}
        ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
        """.format(sub=subject, e_owner=owner, timeofcreation=str(t_event), error_code=str(e_code),
                   error_message=e_message)
    print("LOG [CreateUser]: \n" + msg)
    publish_to_sns(sub, msg)
