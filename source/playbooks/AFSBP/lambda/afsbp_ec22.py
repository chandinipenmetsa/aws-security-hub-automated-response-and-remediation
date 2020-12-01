
#!/usr/bin/python
###############################################################################
#  Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.    #
#                                                                             #
#  Licensed under the Apache License Version 2.0 (the "License"). You may not #
#  use this file except in compliance with the License. A copy of the License #
#  is located at                                                              #
#                                                                             #
#      http://www.apache.org/licenses/                                        #
#                                                                             #
#  or in the "license" file accompanying this file. This file is distributed  #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express #
#  or implied. See the License for the specific language governing permis-    #
#  sions and limitations under the License.                                   #
###############################################################################

import logging
import os
import boto3
import time
import sys
from botocore.exceptions import ClientError

#------------------------------------------------------------------------------
# HANDLER
#------------------------------------------------------------------------------
def lambda_handler(event, context):

    setup_logging()
    log.info(event)
    #==========================================================================
    # parse SG ID from Security Hub CWE

    try:
        #Remediate EC2.2 The VPC default security group should not allow inbound and outbound traffic
        default_sg_id = str(event['detail']['findings'][0]['Resources'][0]['Details']['AwsEc2SecurityGroup']['GroupId'])
        ssm = boto3.client('ssm')
        response = ssm.start_automation_execution(
            # Launch SSM Doc via Automation
            DocumentName='AFSBP-EC22Remediation',
            Parameters={
                'GroupId': [default_sg_id],
                #Change assume role format to dynamic
                'AutomationAssumeRole': [os.environ['IAM_ROLE']]
            }
        )
        log.info("Response: {}".format(response))
        execution_id = response['AutomationExecutionId']
        status = get_execution_status(execution_id)
        log.info("Automation execution status: {}".format(status))

    except Exception as e:
        log.error(e)
        return

def get_execution_status(execution_id):
    try:
        ssm = boto3.client('ssm')
        state = 'Waiting'
        pending_states = ['Pending', 'InProgress', 'Waiting']
        while (state in pending_states):
            time.sleep(3)
            status = ssm.describe_automation_executions(
                Filters = [
                    {
                        'Key': 'ExecutionId',
                        'Values': [execution_id]
                    }
                    ]
                )
            state = status['AutomationExecutionMetadataList'][0]['AutomationExecutionStatus']
            if (state not in pending_states):
                return state
    except Exception as e:
        log.error(e)
        return

def setup_logging():
    """
    Log Function.

    Creates a global log object and sets its level.
    """
    global log
    log = logging.getLogger()
    log_levels = {'INFO': 20, 'WARNING': 30, 'ERROR': 40}

    if 'LOGGING_LEVEL' in os.environ:
        log_level = os.environ['LOGGING_LEVEL'].upper()
        if log_level in log_levels:
            log.setLevel(log_levels[log_level])
        else:
            log.setLevel(log_levels['ERROR'])
            log.error("The LOGGING_LEVEL environment variable is not set" +
                      " to INFO, WARNING, or ERROR. " +
                      "The log level is set to ERROR")
    else:
        log.setLevel(log_levels['ERROR'])
        log.warning("The LOGGING_LEVEL environment variable is not set. " +
                    "The log level is set to ERROR")
    log.info('Logging setup complete - set to log level ' +
             str(log.getEffectiveLevel()))
