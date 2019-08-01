import notify


def event(event_details, event_raw):
    e_name = event_details["eventName"]

    if e_name == "CreateUser":

        event_details["subject"] = event_details["subject"].split("/")[-1]
        if event_details["errorCode"] is None:
            notify.notify_createUser_allowed(subject=event_details["subject"],
                                             owner=event_details["eventOwner"],
                                             t_event=event_details["timestamp"])
        else:
            notify.notify_createUser_denied(subject=event_details["subject"],
                                            owner=event_details["eventOwner"],
                                            t_event=event_details["timestamp"],
                                            e_code=event_details["errorCode"],
                                            e_message=event_details["errorMessage"])

    elif e_name == "DeleteUser" or e_name == "DeleteLoginProfile":
        if event_details["errorCode"] is None:
            notify.notify_deleteUser_allowed(subject=event_details["subject"],
                                             owner=event_details["eventOwner"],
                                             t_event=event_details["timestamp"])
        else:
            notify.notify_deleteUser_denied(subject=event_details["subject"],
                                            owner=event_details["eventOwner"],
                                            t_event=event_details["timestamp"],
                                            e_code=event_details["errorCode"],
                                            e_message=event_details["errorMessage"])

    elif e_name == "AttachUserPolicy":
        if event_details["errorCode"] is None:
            # Extract Policy Name
            policy = event_raw["detail"]["requestParameters"]["policyArn"]
            notify.notify_AttachUserPolicy_allowed(subject=event_details["subject"],
                                                   owner=event_details["eventOwner"],
                                                   policy_arn=policy,
                                                   t_event=event_details["timestamp"])
        else:
            notify.notify_AttachUserPolicy_denied(subject=event_details["subject"],
                                                  owner=event_details["eventOwner"],
                                                  t_event=event_details["timestamp"],
                                                  e_code=event_details["errorCode"],
                                                  e_message=event_details["errorMessage"])
    elif e_name == "DetachUserPolicy":
        if event_details["errorCode"] is None:
            # Extract Policy Name
            policy = event_raw["detail"]["requestParameters"]["policyArn"]
            notify.notify_DetachUserPolicy_allowed(subject=event_details["subject"],
                                                   owner=event_details["eventOwner"],
                                                   policy_arn=policy,
                                                   t_event=event_details["timestamp"])
        else:
            notify.notify_DetachUserPolicy_denied(subject=event_details["subject"],
                                                  owner=event_details["eventOwner"],
                                                  t_event=event_details["timestamp"],
                                                  e_code=event_details["errorCode"],
                                                  e_message=event_details["errorMessage"])
    elif e_name == "CreatePolicy":
        if event_details["errorCode"] is None:
            # Extract Policy Name
            policy = event_raw["detail"]["requestParameters"]["policyName"]
            policy_document = event_raw["detail"]["requestParameters"]["policyDocument"]
            notify.notify_CreatePolicy_allowed(owner=event_details["eventOwner"],
                                               policy_arn=policy,
                                               t_event=event_details["timestamp"],
                                               policy_doc=policy_document)
        else:
            notify.notify_CreatePolicy_denied(owner=event_details["eventOwner"],
                                              t_event=event_details["timestamp"],
                                              e_code=event_details["errorCode"],
                                              e_message=event_details["errorMessage"])
    elif e_name == "DeletePolicy":
        if event_details["errorCode"] is None:
            # Extract Policy Name
            policy = event_raw["detail"]["requestParameters"]["policyArn"]
            notify.notify_DeletePolicy_allowed(owner=event_details["eventOwner"],
                                               policy_arn=policy,
                                               t_event=event_details["timestamp"])
        else:
            notify.notify_DeletePolicy_denied(owner=event_details["eventOwner"],
                                              t_event=event_details["timestamp"],
                                              e_code=event_details["errorCode"],
                                              e_message=event_details["errorMessage"])
    elif e_name == "CreatePolicyVersion":
        if event_details["errorCode"] is None:
            # Extract Policy Name
            policy = event_raw["detail"]["requestParameters"]["policyArn"]
            policy_document = event_raw["detail"]["requestParameters"]["policyDocument"]
            notify.notify_CreatePolicyVersion_allowed(owner=event_details["eventOwner"],
                                                      policy_arn=policy,
                                                      t_event=event_details["timestamp"],
                                                      policy_doc=policy_document)
        else:
            policy = event_details["errorMessage"].split("/")[-1]
            notify.notify_CreatePolicyVersion_denied(subject=event_details["subject"],
                                                     owner=event_details["eventOwner"],
                                                     t_event=event_details["timestamp"],
                                                     e_code=event_details["errorCode"],
                                                     policy_name=policy,
                                                     e_message=event_details["errorMessage"])
