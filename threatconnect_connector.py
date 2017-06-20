# --
# File: threatconnect_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2016-2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
# --

# Phantom imports
import phantom.app as phantom
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

# App-specific imports
from threatconnect_consts import *

# library imports
import requests
import simplejson as json
import hmac
from requests import Request
import time
import hashlib
import base64
import ipaddr
import os
import inspect
from datetime import datetime, timedelta
from urllib import quote_plus
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class ThreatconnectConnector(BaseConnector):

    # List of all of the actions that are available for this app
    ACTION_ID_HUNT_FILE = "hunt_file"
    ACTION_ID_HUNT_HOST = "hunt_host"
    ACTION_ID_HUNT_URL = "hunt_url"
    ACTION_ID_HUNT_EMAIL = "hunt_email"
    ACTION_ID_HUNT_IP = "hunt_ip"
    ACTION_ID_LIST_OWNERS = "list_owners"
    ACTION_ID_POST_DATA = "post_data"
    ACTION_ID_ON_POLL = "on_poll"
    TEST_ASSET_CONNECTIVITY = "test_asset_connectivity"

    def __init__(self):

        super(ThreatconnectConnector, self).__init__()
        self._state = {}

    def _test_connectivity(self, params):

        action_result = self.add_action_result(ActionResult(params))

        self.save_progress("Using base url: {0}".format(self._get_url()))

        self.save_progress("Requesting a list of all owners visible to this user...")

        ret_val, resp_json = self._make_rest_call(action_result, THREATCONNECT_ENDPOINT_TEST)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if not resp_json['status']:
            return action_result.set_status(phantom.APP_ERROR, "There was an error in parsing the response", resp_json)
        elif resp_json['status'] != "Success":
            return action_result.set_status(phantom.APP_ERROR, "Test connectivity failed", resp_json)

        self.save_progress("Test connectivity succeeded")

        return action_result.set_status(phantom.APP_SUCCESS, "Test connectivity succeeded")

    def _list_owners(self, params):

        action_result = self.add_action_result(ActionResult(params))

        self.save_progress("Using base url: {0}".format(self._get_url()))

        self.save_progress("Requesting a list of all owners visible to this user...")

        ret_val, resp_json = self._make_rest_call(action_result, THREATCONNECT_ENDPOINT_TEST)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if not resp_json.get('status'):
            return action_result.set_status(phantom.APP_ERROR, "There was an error in parsing the response", resp_json)
        elif resp_json.get('status') != "Success":
            return action_result.set_status(phantom.APP_ERROR, "Test connectivity failed", resp_json)

        self.save_progress("List owners succeeded.")
        action_result.add_data(resp_json)
        total_objects = int(resp_json['data']['resultCount'])
        action_result.set_summary({"num_owners": total_objects})

        return action_result.set_status(phantom.APP_SUCCESS, "List owners succeeded")

    def _add_attribute(self, action_result, attribute_name, attribute_value, indicator_summary, indicator_type):

        # Create an endpoint specific for posting indicators
        endpoint = THREATCONNECT_ENDPOINT_INDICATOR_BASE + "/" + indicator_type + "/" + quote_plus(indicator_summary) + "/" + "attributes"

        kwargs = {
            "type": attribute_name,
            "value": attribute_value,
            "displayed": True
        }

        ret_val, response = self._make_rest_call(action_result, endpoint, body=kwargs, rtype="POST")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        status = response['status'] if type(response) == dict else THREATCONNECT_STATUS_FAILURE

        if (phantom.is_fail(ret_val)) or status == THREATCONNECT_STATUS_FAILURE:
            # Return a failed action result
            action_result.set_status(phantom.APP_ERROR, "The requested attribute was not found")

            return phantom.APP_ERROR

        return phantom.APP_SUCCESS

    def _hunt_indicator(self, params, hunt_domain=False):

        action_result = self.add_action_result(ActionResult(params))

        # Messy if/else block so that there aren't 5 actions with repeated code
        if (params.get(THREATCONNECT_JSON_IP, None)):
            indicator_to_hunt = params[THREATCONNECT_JSON_IP]
            try:
                ipaddr.IPAddress(indicator_to_hunt)
                endpoint = THREATCONNECT_ENDPOINT_ADDRESS
            except ValueError:
                return action_result.set_status(phantom.APP_ERROR, "Parameter 'ip' failed validation")
        elif (params.get(THREATCONNECT_JSON_FILE, None)):
            indicator_to_hunt = params[THREATCONNECT_JSON_FILE]
            endpoint = THREATCONNECT_ENDPOINT_FILE
        # If the action is hunt domain then it gets really special.  Need to pass domains to host, and urls to url
        elif (params.get(THREATCONNECT_JSON_DOMAIN, None)):
            # NEED SOME EXTRA SANITATION ON THE DATA BEFORE IT GETS PASSED OVER
            hunt_me = params.get(THREATCONNECT_JSON_DOMAIN)
            if phantom.is_domain(hunt_me):
                indicator_to_hunt = hunt_me
                endpoint = THREATCONNECT_ENDPOINT_HOST
            elif phantom.is_url(hunt_me):
                indicator_to_hunt = hunt_me
                endpoint = THREATCONNECT_ENDPOINT_URL
            else:
                return action_result.set_status(phantom.APP_ERROR, "Could not resolve parameter type")
        elif (params.get(THREATCONNECT_JSON_URL, None)):
            indicator_to_hunt = params[THREATCONNECT_JSON_URL]
            endpoint = THREATCONNECT_ENDPOINT_URL
        elif (params.get(THREATCONNECT_JSON_EMAIL, None)):
            indicator_to_hunt = params[THREATCONNECT_JSON_EMAIL]
            endpoint = THREATCONNECT_ENDPOINT_EMAIL

        # Encodes any fishy values...  ESPECIALLY THAT PESKY PLUS SIGN
        indicator_to_hunt = quote_plus(indicator_to_hunt)

        endpoint_uri = THREATCONNECT_ENDPOINT_INDICATOR_BASE + "/" + endpoint

        if (params.get(THREATCONNECT_JSON_OWNER, None)):
            owners_list = []
            owners = params.get(THREATCONNECT_JSON_OWNER, None)

            # First work on the comma as the seperator
            if type(owners) is list:
                owners_list = owners
            elif (',' in owners):
                owners_list = owners.split(',')
            elif(';' in owners):
                owners_list = owners.split(';')
            else:
                owners_list.append(owners)

            total_objects = 0
            for owner in owners_list:
                owner = quote_plus(owner)
                kwargs = json.dumps('filters=summary=' + indicator_to_hunt + '&owner=' + owner).replace('"', "")
                # Make the rest call
                ret_val, response = self._make_rest_call(action_result, endpoint_uri, params=kwargs)

                if (phantom.is_fail(ret_val)):
                    return action_result.get_status()

                if (response['status'] == THREATCONNECT_STATUS_FAILURE):
                    return action_result.set_status(phantom.APP_ERROR, "Response failed", response['message'])

                action_result.add_data(response)
                total_objects += int(response['data']['resultCount'])

            action_result.set_summary({"total_objects": total_objects})

        else:
            # Dumping the string causes quotes to show up and neither me or ThreatConnect likes that
            kwargs = json.dumps('filters=summary=' + indicator_to_hunt).replace('"', "")

            # Make the rest call
            ret_val, response = self._make_rest_call(action_result, endpoint_uri, params=kwargs)

            if (phantom.is_fail(ret_val)):
                return action_result.get_status()

            if (response['status'] == THREATCONNECT_STATUS_FAILURE):
                return action_result.set_status(phantom.APP_ERROR, "Response failed", response['message'])

            action_result.add_data(response)
            action_result.set_summary({"total_objects": response['data']['resultCount']})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _post_data(self, params):

        action_result = self.add_action_result(ActionResult(params))

        primary_field = params[THREATCONNECT_JSON_PRIMARY_FIELD]

        attribute_name = params.get(THREATCONNECT_JSON_ATTRIBUTE_NAME)

        attribute_value = params.get(THREATCONNECT_JSON_ATTRIBUTE_VALUE)

        files = None

        if ("," in primary_field):

            files = {}

            for value in primary_field.split(','):

                indicator_type, endpoint = self._get_data_type(value.strip(' '))

                if (phantom.is_fail(indicator_type)):
                    return action_result.set_status(phantom.APP_ERROR, endpoint)

                files[indicator_type] = value.strip(' ')
        else:
            indicator_type, endpoint = self._get_data_type(primary_field)

            if (phantom.is_fail(indicator_type)):
                return action_result.set_status(phantom.APP_ERROR, endpoint)

        endpoint_uri = THREATCONNECT_ENDPOINT_INDICATOR_BASE + '/' + endpoint

        # Build the kwargs to be sent over by SpaceX ship
        kwargs = {}
        kwargs[indicator_type] = primary_field
        kwargs['rating'] = params.get(THREATCONNECT_JSON_RATING, None)
        kwargs['confidence'] = params.get(THREATCONNECT_JSON_CONFIDENCE, None)
        if (endpoint == THREATCONNECT_ENDPOINT_FILE):
            kwargs['size'] = params.get(THREATCONNECT_JSON_SIZE, None)
            if files:
                kwargs.update(files)
        elif (endpoint == THREATCONNECT_ENDPOINT_HOST):
            kwargs['dnsActive'] = params.get(THREATCONNECT_JSON_DNSACTIVE, None)
            kwargs['whoisActive'] = params.get(THREATCONNECT_JSON_WHOISACTIVE, None)

        ret_val, response = self._make_rest_call(action_result, endpoint_uri, body=kwargs, rtype=THREATCONNECT_POST)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        else:
            # Gets to this block if the indicator is new and posted and great and successful

            if (attribute_name and attribute_value):

                if files:
                    # The indicator endpoint is only dependent on the first hash within the parameter
                    primary_field = primary_field.split(',')[0].strip(' ')

                ret_val = self._add_attribute(action_result, attribute_name, attribute_value, primary_field, endpoint)

                if (phantom.is_fail(ret_val)):

                    action_result.add_data(response)
                    # Update the summary and give a helpful response
                    action_result.set_summary({"total_objects": 1,
                                               "indicator_created/updated": True,
                                               "attribute_added": False})

                    return action_result.set_status(phantom.APP_ERROR, "Indicator created/updated, but failed to update the attribute specified. "
                                                                       "Please ensure the attribute_name is valid, is applicable to the indicator "
                                                                       "type and attribute_value is valid")
                else:

                    action_result.add_data(response)

                    action_result.set_summary({"total_objects": 1,
                                               "indicator_created/updated": True,
                                               "attribute_added": True})

                    return action_result.set_status(phantom.APP_SUCCESS, "Data successfully posted to ThreatConnect.  Attribute addition succeeded")

            action_result.add_data(response)

            action_result.set_summary({"total_objects": 1,
                                       "indicator_created/updated": True,
                                       "attribute_added": False})

            return action_result.set_status(phantom.APP_SUCCESS, "Data successfully posted to ThreatConnect")

    def _on_poll(self, params):

        action_result = self.add_action_result(ActionResult(dict(params)))

        last_time = self._state.get(THREATCONNECT_JSON_LAST_DATE_TIME)

        config = self.get_config()

        if (self.is_poll_now()):

            num_of_days = int(config.get(THREATCONNECT_JSON_DEF_NUM_DAYS, THREATCONNECT_DAYS_TO_POLL))

            start_time = datetime.utcfromtimestamp(time.time() - (num_of_days * THREATCONNECT_SECONDS_IN_A_DAY)).strftime(DATETIME_FORMAT)

            self._container_limit = int(params[THREATCONNECT_CONFIG_POLL_NOW_CONTAINER_LIMIT])

        else:

            self._container_limit = int(config.get(THREATCONNECT_JSON_CONTAINER_LIMIT, THREATCONNECT_CONTAINER_LIMIT_DEFAULT))

            num_of_days = int(config.get(THREATCONNECT_JSON_DEF_NUM_DAYS, THREATCONNECT_DAYS_TO_POLL))

            if (self._state.get('first_run', True)):

                # Only goes here when its the first time polling with on_poll
                self._state['first_run'] = False

                start_time = self._first_poll(num_of_days)

            elif (last_time):

                # Last polled time is taken here
                start_time = last_time

        self.save_progress("Start time for polling: {0}".format(start_time))

        self.save_progress("Querying for Indicators created between {} and {}".format(datetime.utcnow().strftime(DATETIME_FORMAT), start_time))

        self.save_progress("Making REST call for ingestion")

        endpoint = THREATCONNECT_ENDPOINT_INDICATOR_BASE

        ret_val, resp_json = self._make_rest_call(action_result, endpoint)

        if (phantom.is_fail(ret_val)):
            self.save_progress("REST Call failed during ingestion")

            return self.set_status(phantom.APP_ERROR)

        self.save_progress("Saving containers and artifacts")

        ret_val, message = self._create_containers(resp_json, start_time)

        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_ERROR, message)

        return action_result.set_status(phantom.APP_SUCCESS, "Polling has succeeded")

    def _first_poll(self, number_of_days):
        '''
        First poll will get the UNIX time for number_of_days ago and then convert it into zulu format
        '''
        return datetime.utcfromtimestamp(time.time() - (number_of_days * THREATCONNECT_SECONDS_IN_A_DAY)).strftime(DATETIME_FORMAT)

    def _create_containers(self, resp_json, start_time):
        """ Returns 2 values, use RetVal """

        # List of indicators that have been passed over... To be reversed later when written yanno????
        possible_indicators = []

        # Convert the start_time determined by on_poll to UNIX timestamp to compare to the indicator
        start_time_unix = int(datetime.strptime(start_time, DATETIME_FORMAT).strftime("%s"))

        # Iterate through all the indicators starting at the top of the list (which should be most recent)
        for indicator in resp_json['data']['indicator']:

            # Convert the indicator's dateAdded string to a UNIX timestamp to make life easier for everyone
            indicator_date_added_unix = int(datetime.strptime(indicator['dateAdded'], DATETIME_FORMAT).strftime("%s"))

            # Add the indicator to save it for later because runtime is important!!!
            possible_indicators.append(indicator)

            # If the indicator is passed up and it's not the oldest possible one, save it for later
            if (start_time_unix < indicator_date_added_unix):
                continue
            # Successfully found the indicator to stop at.
            elif (start_time_unix > indicator_date_added_unix):

                ret_val, message = self._iterate_indicators(possible_indicators)
                if phantom.is_fail(ret_val):
                    return RetVal(phantom.APP_ERROR, message)

                return RetVal(phantom.APP_SUCCESS, message)

        if len(possible_indicators) == 0:
            return RetVal(phantom.APP_SUCCESS, "No new indicators")  # NO NEW INDICATORS

        ret_val, message = self._iterate_indicators(possible_indicators)

        if phantom.is_fail(ret_val):
            return RetVal(phantom.APP_ERROR, message)

        return RetVal(phantom.APP_SUCCESS, "Success")

    def _iterate_indicators(self, indicator_list):
        '''
        Iterates through the recorded indicators in to ingest the correct containers count
        '''
        container_limit = self._container_limit if self._container_limit < len(indicator_list) else len(indicator_list)

        successful_container_count = 0

        beginning_of_polling_date = indicator_list[-1]['dateAdded']

        for indicator in reversed(indicator_list):

            # Required fields that are present in every Indicator
            required_fields = {
                "summary": str(indicator['summary']),
                "indicator_type": str(indicator['type']).lower(),
                "date_created": str(indicator['dateAdded']),
                "date_modified": str(indicator['lastModified']),
                "indicator_id": indicator['id']
            }

            # Optional fields that are not present in every indicator but we want to ingest them anyways
            optional_cef_fields = {
                "rating": indicator.get("rating"),
                "confidence": indicator.get("confidence"),
                "threatAssessRating": indicator.get("threatAssessRating"),
                "threatAssessConfidence": indicator.get("threatAssessConfidence")
            }
            # Retrieve any extra data needed in the artifact (i.e., extra file hashes)
            extra_data = self._get_extra_data(required_fields)

            # Get the needed artifact details
            cef_name, cef_field, cef_type = self._get_cef_details(required_fields)

            # Create the necessary container and artifact dicts with necessary fields
            container, artifact = self._get_base_dicts(required_fields, cef_name)

            # Add any additional CEF fields to the artifact
            artifact = self._get_optional_cef_fields(required_fields, artifact, optional_cef_fields, extra_data, cef_name, cef_field, cef_type)

            # Create the container
            ret_val, container_message, id = self.save_container(container)

            # Increment the container count
            successful_container_count += 1

            # Pull the ID from the container and add it to the artifact
            artifact['container_id'] = id

            # Add the artifact to that container
            ret_val, artifact_message, id = self.save_artifact(artifact)

            # Break the loop when the container_limit set in the config is reached.
            if successful_container_count == container_limit:

                # Only update the state file if its not poll now
                if phantom.is_fail(self.is_poll_now()):

                    # Update the state in order to use the correct date for the next ingestion cycle.
                    date_to_use = self._state.get(THREATCONNECT_JSON_LAST_DATE_TIME)

                    if date_to_use is None:

                        date_to_use = beginning_of_polling_date

                    if date_to_use == indicator['dateAdded']:

                        # If it's the same date make sure that there have been no containers added (this would mean it caught up)
                        if "duplicate" in container_message:
                            return phantom.APP_SUCCESS, "No new indicators found"

                        start_time = (datetime.strptime(indicator['dateAdded'], DATETIME_FORMAT) + timedelta(seconds=1)).strftime(
                            DATETIME_FORMAT)

                        self._state[THREATCONNECT_JSON_LAST_DATE_TIME] = start_time

                        return phantom.APP_ERROR, "Some indicators may have been dropped due to max containers being smaller than the amount of indicators" \
                                                  " in a given second.  Please increase the max_containers in order to ensure no dropped indicators."
                    else:
                        # As long as the indicator date and the date in the state are not the same then replace it
                        self._state[THREATCONNECT_JSON_LAST_DATE_TIME] = indicator['dateAdded']
                break

        return phantom.APP_SUCCESS, "Success"

    def _get_optional_cef_fields(self, required_fields, artifact_base, optional_cef_fields, extra_data, cef_name, cef_field, cef_type):

        updated_artifact = artifact_base
        summary = required_fields['summary']
        indicator_type = required_fields['indicator_type']

        # Add the common optional fields first
        if optional_cef_fields['rating']:
            updated_artifact['cef'].update({'rating': str(optional_cef_fields['rating'])})
        if optional_cef_fields['confidence']:
            updated_artifact['cef'].update({'confidence': optional_cef_fields['confidence']})
        if optional_cef_fields['threatAssessRating']:
            updated_artifact['cef'].update({'threatAssessRating': optional_cef_fields['threatAssessRating']})
        if optional_cef_fields['threatAssessConfidence']:
            updated_artifact['cef'].update({'threatAssessConfidence': optional_cef_fields['threatAssessConfidence']})

        # Add the indicator under the cef field cn1 if the type could not be determined
        if not cef_name and not cef_field and not cef_type:
            updated_artifact['cef'].update({'ioc': required_fields['summary']})

        # Specific formatting for CIDR indicators
        elif (cef_name == "CIDR Artifact"):
            updated_artifact['cef'].update({
                cef_field[0]: required_fields['summary'].split("/")[0],
                cef_field[1]: required_fields['summary'].split("/")[1],
                cef_field[2]: required_fields['summary']
            })
            updated_artifact['cef_types'] = {
                cef_field[0]: [cef_type[0]],
                cef_field[2]: [cef_type[2]]
            }

        # Specific formatting for Registry Key indicators
        elif (cef_name == "Registry Key Artifact"):
            registry, value_name, value_type = required_fields['summary'].split(" : ")
            updated_artifact['cef'].update({
                "registryKey": registry,
                "registryValue": value_name,
                "registryType": value_type
            })
        elif indicator_type == "file":
            if extra_data['md5']:
                updated_artifact['cef'].update({'fileHashMd5': extra_data['md5']})
                updated_artifact['cef_types'].update({'fileHashMd5': ["md5"]})
            if extra_data['sha1']:
                updated_artifact['cef'].update({'fileHashSha1': extra_data['sha1']})
                updated_artifact['cef_types'].update({'fileHashSha1': ["sha1"]})
            if extra_data['sha256']:
                updated_artifact['cef'].update({'fileHashSha256': extra_data['sha256']})
                updated_artifact['cef_types'].update({'fileHashSha256': ["sha256"]})

        # Final clause if the cef name is not listed above and if the indicator is not a file
        else:
            updated_artifact['cef'].update({cef_field: summary})
            if cef_type:
                updated_artifact['cef_types'].update({cef_field: [cef_type]})

        return updated_artifact

    def _get_base_dicts(self, required_fields, cef_name):
        '''
        Creates the container and artifact dict with values that are absolutely required.
        :return: base container, base artifact
        '''
        indicator_id = required_fields['indicator_id']
        container = {
            "name": THREATCONNECT_INGEST_CONTAINER_NAME.format(summary=required_fields['summary']),
            "description": "Ingested indicator from ThreatConnect",
            "source_data_identifier": indicator_id
        }

        artifact = {
            "container_id": None,
            "label": "event",
            "type": "None",
            "name": cef_name,
            "source_data_identifier": indicator_id,
            "cef": {
                'deviceCustomDate1': required_fields['date_created'],
                'deviceCustomDate1Label': "Date Created",
                'deviceCustomDate2': required_fields['date_modified'],
                'deviceCustomDate2Label': "Last Modified"
            },
            "cef_types": {}
        }
        return container, artifact

    def _get_extra_data(self, required_fields):
        '''
        Gets any extra data that the indicator might have, i.e., extra hashes for file indicators.
        :param indicator_type: Required fields dict
        :return: dict of extra data,
        '''
        extra_data = {}
        if required_fields['indicator_type'] == 'file':
            # Dumping the string causes quotes to show up and neither me or ThreatConnect likes that
            kwargs = json.dumps('filters=summary=' + required_fields['summary']).replace('"', "")
            endpoint_uri = THREATCONNECT_ENDPOINT_INDICATOR_BASE + "/" + 'files'

            # Make the rest call
            action_result = ActionResult()
            ret_val, response = self._make_rest_call(action_result, endpoint_uri, params=kwargs)
            if (phantom.is_fail(ret_val)):
                return extra_data

            extra_data['md5'] = response['data']['file'][0].get('md5', None)
            extra_data['sha1'] = response['data']['file'][0].get('sha1', None)
            extra_data['sha256'] = response['data']['file'][0].get('sha256', None)

        return extra_data

    def _get_data_type(self, primary_field):
        """ Returns two Values, use RetVal """

        try:
            ipaddr.IPAddress(primary_field)
            return RetVal('ip', THREATCONNECT_ENDPOINT_ADDRESS)
        except ValueError:
            if (phantom.is_email(primary_field)):
                return RetVal('address', THREATCONNECT_ENDPOINT_EMAIL)
            elif (phantom.is_md5(primary_field)):
                return RetVal('md5', THREATCONNECT_ENDPOINT_FILE)
            elif (phantom.is_sha1(primary_field)):
                return RetVal('sha1', THREATCONNECT_ENDPOINT_FILE)
            elif (phantom.is_sha256(primary_field)):
                return RetVal('sha256', THREATCONNECT_ENDPOINT_FILE)
            elif (phantom.is_url(primary_field)):
                return RetVal('text', THREATCONNECT_ENDPOINT_URL)
            elif (phantom.is_domain(primary_field)):
                if "." in primary_field:
                    return RetVal('hostName', THREATCONNECT_ENDPOINT_HOST)
        return RetVal(phantom.APP_ERROR, THREATCONNECT_NO_ENDPOINT_ERR)

    def _get_cef_details(self, required_fields):
        #  Indicator types are value checked because the rest of the indicators, to check are ones with only one type.
        # Address indicators for example will have IPv4, IPv6, etc.
        indicator_type = required_fields['indicator_type']
        summary = required_fields['summary']
        if (indicator_type == "mutex"):
            return "Mutex Artifact", "mutex", None
        if (indicator_type == "cidr"):
            return "CIDR Artifact", ["deviceAddress", "cidrPrefix", "cidr"], ["ip", None, "CIDR"]
        elif (indicator_type == "registry key"):
            return "Registry Key Artifact", "registryKey", None
        elif (indicator_type == "asn"):
            return "ASN Artifact", "asn", None
        elif (indicator_type == "user agent"):
            return "User Agent Artifact", "requestClientApplication", None
        elif (phantom.is_email(summary)):
            return "Email Address Artifact", "emailAddress", "email"
        elif (phantom.is_md5(summary)):
            return "File Artifact", "fileHash", "md5"
        elif (phantom.is_sha1(summary)):
            return "File Artifact", "fileHash", "sha1"
        elif (phantom.is_sha256(summary)):
            return "File Artifact", "fileHash", "sha256"
        elif (phantom.is_url(summary)):
            return "URL Artifact", "requestURL", "url"
        elif (phantom.is_ip(summary)):
             return "IP Artifact", "deviceAddress", "ip"
        try:
            # Check for IPV6
            ipaddr.IPAddress(summary)
            return "IP Artifact", "deviceCustomIPv6Address1", "ipv6"
        except:
            if (phantom.is_domain(summary)):
                return "Domain Artifact", "deviceDnsDomain", "domain"
            return None, None, None

    def _create_header(self, endpoint, params={}, json={}, rtype=THREATCONNECT_GET):
        config = self.get_config()

        api_id = config[THREATCONNECT_CONFIG_ACCESS_ID]
        secret_key = config[THREATCONNECT_CONFIG_SECRET_KEY]
        url = self._get_url() + endpoint

        # ITS "TIME" TO AUTHENTICATE
        # ThreatConnect likes it in this format
        timestamp_nonce = str(int(time.time()))
        # Prepare the url in case there are params that need to be encoded
        encoded_url = Request(rtype, url, params=params, json=json).prepare().path_url
        # Prepare the signature to be signed by the HMAC
        signature_raw = "{0}:{1}:{2}".format(encoded_url, rtype.upper(), timestamp_nonce)
        # Autograph time
        signature_hmac = hmac.new(str(secret_key), signature_raw, digestmod=hashlib.sha256).digest()
        # Formatting ThreatConnect's 'unique' auth field
        authorization = 'TC {0}:{1}'.format(api_id, base64.b64encode(signature_hmac))

        header = {'Content-Type': 'application/json', 'Timestamp': timestamp_nonce, 'Authorization': authorization}

        return header

    def _process_empty_reponse(self, response, action_result):

        if (200 <= response.status_code < 205):
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, is bound to be an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse response as JSON", e), None)

        if (200 <= r.status_code < 205):
            return RetVal(phantom.APP_SUCCESS, resp_json)

        action_result.add_data(resp_json)
        message = r.text.replace('{', '{{').replace('}', '}}')
        return RetVal( action_result.set_status( phantom.APP_ERROR, "Error from server, Status Code: {0} data returned: {1}".format(r.status_code, message)), resp_json)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if an error occurs
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})
            action_result.add_debug_data({'r_status_code': r.status_code})

        # There are just too many differences in the response to handle all of them in the same function
        if ('json' in r.headers.get('Content-Type', '')):
            return self._process_json_response(r, action_result)

        if ('html' in r.headers.get('Content-Type', '')):
            return self._process_html_response(r, action_result)

        # it's not an html or json, handle if it is a successfull empty reponse
        if (200 <= r.status_code < 205) and (not r.text):
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, action_result, endpoint, params={}, body={}, rtype=THREATCONNECT_GET):
        """ Returns 2 values, use RetVal """

        url = self._get_url() + endpoint

        headers = self._create_header(endpoint, params=params, rtype=rtype, json=body)

        try:
            request_func = getattr(requests, rtype)
        except AttributeError:
            # Set the action_result status to error, the handler function will most probably return as is
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unsupported method: {0}".format(rtype)), None)
        except Exception as e:
            # Set the action_result status to error, the handler function will most probably return as is
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Handled exception: {0}".format(str(e))), None)

        try:
            response = request_func(url, params=params, json=body, headers=headers)
        except Exception as e:
            # Set the action_result status to error, the handler function will most probably return as is
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error connecting: {0}".format(str(e))), None)

        # Added line
        try:
            self.debug_print("raw_response: ", response.json())
        except:
            self.debug_print("text_raw_response: ", response.text)

        return self._process_response(response, action_result)

    def _get_url(self):

        config = self.get_config()
        if 'sandbox.threatconnect.com' in config[THREATCONNECT_BASE_URL]:
            return THREATCONNECT_SANDBOX_API_URL.format(base=config[THREATCONNECT_BASE_URL]) + "/"
        else:
            return THREATCONNECT_API_URL.format(base=config[THREATCONNECT_BASE_URL]) + "/"

    def _load_state(self):

        # get the directory of the class
        dirpath = os.path.dirname(inspect.getfile(self.__class__))
        asset_id = self.get_asset_id()
        self._state_file_path = "{0}/{1}_serialized_data.json".format(dirpath, asset_id)
        try:
            with open(self._state_file_path, 'r') as f:
                in_json = f.read()
                self._state = json.loads(in_json)
        except Exception as e:
            self.debug_print("In _load_state: Exception: {0}".format(str(e)))
            pass
        self.debug_print("Loaded state: ", self._state)
        return phantom.APP_SUCCESS

    def _save_state(self):

        self.debug_print("Saving state: ", self._state)
        if (not self._state_file_path):
            self.debug_print("_state_file_path is None in _save_state")
            return phantom.APP_SUCCESS
        try:
            with open(self._state_file_path, 'w+') as f:
                f.write(json.dumps(self._state))
        except Exception as e:
            self.debug_print("Exception in _save_state", e)
            pass
        return phantom.APP_SUCCESS

    def initialize(self):
        self._load_state()
        config = self.get_config()
        config[THREATCONNECT_BASE_URL] = config[THREATCONNECT_BASE_URL].rstrip('/')

        return phantom.APP_SUCCESS

    def finalize(self):
        self._save_state()
        return phantom.APP_SUCCESS

    def handle_action(self, param):
        '''
        This function handles all of the actions that the app can handle.

        '''
        action = self.get_action_identifier()

        ret_val = phantom.APP_SUCCESS

        # Find the correct action to use
        if (action == self.ACTION_ID_POST_DATA):
            ret_val = self._post_data(param)
        elif (action == self.TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity(param)
        elif (action == self.ACTION_ID_HUNT_IP):
            ret_val = self._hunt_indicator(param)
        elif (action == self.ACTION_ID_HUNT_FILE):
            ret_val = self._hunt_indicator(param)
        elif (action == self.ACTION_ID_HUNT_HOST):
            ret_val = self._hunt_indicator(param, hunt_domain=True)
        elif (action == self.ACTION_ID_HUNT_EMAIL):
            ret_val = self._hunt_indicator(param)
        elif (action == self.ACTION_ID_HUNT_URL):
            ret_val = self._hunt_indicator(param)
        elif (action == self.ACTION_ID_LIST_OWNERS):
            ret_val = self._list_owners(param)
        elif (action == self.ACTION_ID_ON_POLL):
            ret_val = self._on_poll(param)

        return ret_val


if __name__ == '__main__':
    '''
    Code that is executed when run in standalone debug mode.  Useful for debugging specific actions, given an action run json

    '''
    # Debugging imports
    import sys
    import pudb

    # Breakpoint at runtime
    pudb.set_trace()
    # The first param when calling is the input json file
    with open(sys.argv[1]) as f:
        # Load the input as JSON
        in_json = json.loads(f.read())
        print (json.dumps(in_json, indent=' ' * 4))
        # Create the connector class object
        connector = ThreatconnectConnector()
        # Set the member variables
        connector.print_progress_message = True
        # Call the Base Connector's handle_action to kick off action handling
        ret_val = connector._handle_action(json.dumps(in_json), None)
        # Dump the return value
        print ret_val
    exit(0)
