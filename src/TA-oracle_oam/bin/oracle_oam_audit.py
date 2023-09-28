import sys
import socket
import requests
from requests.auth import HTTPBasicAuth
from datetime import datetime, timedelta
import urllib.parse
import xmltodict
import time
import json
from splunklib.modularinput import *
import splunklib.client as client


class OracleAccessManagement(Script):

    MASK = "***ENCRYPTED***"
    CREDENTIALS = None

    def get_scheme(self):

        scheme = Scheme("Oracle Access Management")
        scheme.use_external_validation = False
        scheme.use_single_instance = False
        scheme.description = "The Oracle Access Management APIs for Audit Events"

        base_url = Argument("base_url")
        base_url.title = "Tenant hostname"
        base_url.data_type = Argument.data_type_string
        base_url.description = "Example: https://customer.login.us2.oraclecloud.com"
        base_url.required_on_create = True
        base_url.required_on_edit = True
        scheme.add_argument(base_url)

        oam_username = Argument("oam_username")
        oam_username.title = "Username"
        oam_username.data_type = Argument.data_type_string
        oam_username.description = "Supply the HTTP Basic Auth Username"
        oam_username.required_on_create = True
        oam_username.required_on_edit = True
        scheme.add_argument(oam_username)
        
        oam_password = Argument("oam_password")
        oam_password.title = "Password"
        oam_password.data_type = Argument.data_type_string
        oam_password.description = "Supply the HTTP Basic Auth Password, which will be encrypted right away"
        oam_password.required_on_create = True
        oam_password.required_on_edit = False
        scheme.add_argument(oam_password)

        return scheme
        
    def validate_input(self, definition):
        pass

    def encrypt_keys(self, _oam_username, _oam_password, _session_key):

        args = {'token': _session_key}
        service = client.connect(**args)

        credentials = {"oamUsername": _oam_username, "oamPassword": _oam_password}

        try:
            for storage_password in service.storage_passwords:
                if storage_password.username == _oam_username:
                    service.storage_passwords.delete(username=storage_password.username)
                    break

            service.storage_passwords.create(json.dumps(credentials), _oam_username)

        except Exception as e:
            raise Exception("Error encrypting: %s" % str(e))

    def mask_credentials(self, _input_name, _session_key, _base_url, _oam_username):

        try:
            args = {'token': _session_key}
            service = client.connect(**args)

            kind, _input_name = _input_name.split("://")
            item = service.inputs.__getitem__((_input_name, kind))

            kwargs = {
                "base_url": _base_url,
                "oam_username": _oam_username,
                "oam_password": self.MASK
            }

            item.update(**kwargs).refresh()

        except Exception as e:
            raise Exception("Error updating inputs.conf: %s" % str(e))

    def decrypt_keys(self, _oam_username, _session_key):

        args = {'token': _session_key}
        service = client.connect(**args)

        for storage_password in service.storage_passwords:
            if storage_password.username == _oam_username:
                return storage_password.content.clear_password
    
    def get_oam_audit_events(self, base_url, username, password, interval=900):
        
        ENDPOINT = "/oam/services/rest/access/api/v1/audit/events/1"
        
        interval = interval + 60

        from_date = (datetime.utcnow() - timedelta(minutes=interval)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        to_date = (datetime.utcnow() - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        url = f"{base_url}{ENDPOINT}?fromDate={from_date}&toDate={to_date}&pageSize=10000"
        
        encoded_url = urllib.parse.quote(url, safe=':/?&=')
        
        headers = {
            "Content-Type": "application/vnd.oracle.adf.resourceitem+json"
        }
        
        response = requests.get(encoded_url, headers=headers, auth=HTTPBasicAuth(username, password))
        
        return response

    def stream_events(self, inputs, ew):
        
        start = time.time()
        presult = ""
        
        self.input_name, self.input_items = inputs.inputs.popitem()
        session_key = self._input_definition.metadata["session_key"]
        base_url = self.input_items["base_url"]
        oam_username = self.input_items["oam_username"]
        oam_password = self.input_items["oam_password"]
        interval = self.input_items["interval"]
        
        interval = interval if isinstance(interval, (int)) else 900
        
        ew.log("INFO", f'Collecting Oracle Access Management logs from API: {str(base_url)} using credentials from {oam_username}. Interval is every {str(interval)} seconds.')

        try:
            
            if oam_password != self.MASK:
                self.encrypt_keys(oam_username, oam_password, session_key)
                self.mask_credentials(self.input_name, session_key, base_url, oam_username)

            decrypted = self.decrypt_keys(oam_username, session_key)
            self.CREDENTIALS = json.loads(decrypted)

            oam_password = self.CREDENTIALS["oamPassword"]

            result = self.get_oam_audit_events(base_url, oam_username, oam_password, interval)

            status_code = result.status_code

            if status_code != 200:
                ew.log("ERROR", "Unsuccessful HTTP request for Oracle Access Management Logs. status_code=: %s" % str(status_code))
                sys.exit(1)
                
            result_json = xmltodict.parse(result.content)
            
            ew.log("INFO", f'Successful API call for Oracle Access Management Logs. Writing results now to Splunk event writer.')
            
            apiScriptHost = socket.gethostname()
            
            if 'Events' in result_json and 'eventData' in result_json['Events']:
                eventData = result_json['Events']['eventData']
                for event in eventData:
                    event["baseUrl"] = base_url
                    event["apiScriptHost"] = apiScriptHost
                    splunkEvent = Event()
                    splunkEvent.stanza = self.input_name
                    splunkEvent.sourceType = "oracle:oam:auditevents"
                    splunkEvent.host = base_url
                    splunkEvent.data = json.dumps(event)
                    ew.write_event(splunkEvent)
                
            else:
                ew.log("INFO", f"No eventData found.")

                    
            ew.log("INFO", f'Successfully written OAM logs.')

            presult = "completed"
        
        except Exception as e:
            presult = "failed"
            ew.log("ERROR", f"Error: {e}")
        
        end = time.time()
        elapsed = round((end - start) * 1000, 2)
        ew.log("INFO", f'Process {presult} in {str(elapsed)} ms. input_name="{self.input_name}"')


if __name__ == "__main__":
    sys.exit(OracleAccessManagement().run(sys.argv))
