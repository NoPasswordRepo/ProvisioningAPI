import configparser
import base64
from _datetime import datetime
import json

import requests
from http import HTTPStatus

from AESCipher import AESCipher
from RSACipher import RSACipher


class UsersProvisioning(object):
    UTF_ENCODING = "utf-16le"
    APPLICATION_JSON = "application/json"

    def __init__(self, pub_key, priv_key):
        config = configparser.RawConfigParser()
        config.read('config.properties')
        self.GENERIC_API_KEY = config.get("Provisioning", "generic_api_key")
        self.BASE_URL = config.get("Provisioning", "provisioning_url")
        self.ADD_USER_URL = self.BASE_URL + "AddUser"
        self.EDIT_USER_URL = self.BASE_URL + "EditUser"
        self.DELETE_USER_URL = self.BASE_URL + "DeleteUser"
        self.SUSPEND_USER_URL = self.BASE_URL + "SuspendUser"
        self.RESEND_ACTIVATION_EMAIL_URL = self.BASE_URL + "ResendActivationEmail"
        self.PUBLIC_KEY_REGISTRATION_URL = self.BASE_URL + "PKReg"
        self.IS_USER_EXISTS_URL = self.BASE_URL + "IsUserExist"
        self.ADD_GROUP_URL = self.BASE_URL + "AddGroup"
        self.DELETE_GROUP_URL = self.BASE_URL + "DeleteGroup"
        self.ASSIGN_GROUP_MEMBER_URL = self.BASE_URL + "AssignGroupMember"
        self.UNASSIGN_GROUP_MEMBER_URL = self.BASE_URL + "UnassignGroupMember"
        self.POST_ROLE_URL = self.BASE_URL + "PostRole"
        self.GET_ROLES_URL = self.BASE_URL + "GetRoles"
        self.DELETE_ROLE_URL = self.BASE_URL + "DeleteRole"
        self.ASSIGN_TO_ROLE_URL = self.BASE_URL + "AssignToRole"
        self.GET_ASSIGNED_TO_ROLE_URL = self.BASE_URL + "GetAssignedToRole"
        self.rsaCipher = RSACipher(pub_key, priv_key, self.UTF_ENCODING)
        self.trimmed_pub_key = pub_key \
            .replace("-----BEGIN PUBLIC KEY-----", "") \
            .replace("-----END PUBLIC KEY-----", "") \
            .replace("\n", "")

    # Users

    def is_user_exists(self, email):
        """Checks if users exists
        :rtype: bool
        :param email: user email address
        :return: True if user exists
        """
        response = self.send_request_and_parse(email, self.IS_USER_EXISTS_URL)
        return response["Succeeded"]

    def add_user(self, user: dict):
        """Adds an user
        :rtype: bool
        :param user: User dictionary:
        {
             "Email" = "email@test.com",
             "SecondaryEmail" = "email2@test.com",
             "FirstName" = "First,
             "LastName" = "Last",
             "PhoneNumber" = "(555) 555-55-55",
             "EmployeeID" = "EmployeeID",
             "Department" = "Department",
             "Description" = "Description",
             "SamAccountName" = "SamAccountName",
             "OU" = "Organization unit"
             'Attributes" = [{ Name: "Attr 1", Value: "Value 1"}, { Name: "Attr 2", Value: "Value 2"}]
         }
        :return: True if user has been successfully added
        """
        response = self.send_request_and_parse(user, self.ADD_USER_URL)
        return response["Succeeded"]

    def edit_user(self, user):
        """Edits an user
        :rtype: bool
        :param user: User dictionary:
        {
             "Email" = "email@test.com",
             "SecondaryEmail" = "email2@test.com",
             "FirstName" = "First,
             "LastName" = "Last",
             "PhoneNumber" = "(555) 555-55-55",
             "EmployeeID" = "EmployeeID",
             "Department" = "Department",
             "Description" = "Description",
             "SamAccountName" = "SamAccountName",
             "OU" = "Organization unit"
             'Attributes" = [{ Name: "Attr 1", Value: "Value 1"}, { Name: "Attr 2", Value: "Value 2"}]
         }
        :return: True if user has been successfully edited
        """
        response = self.send_request_and_parse(user, self.EDIT_USER_URL)
        return response["Succeeded"]

    def delete_user(self, email):
        """Deletes an user
        :rtype: bool
        :param email: User email
        :return: True if user has been successfully deleted
        """
        response = self.send_request_and_parse(email, self.DELETE_USER_URL)
        return response["Succeeded"]

    def suspend_user(self, email):
        """Suspends an user
        :rtype: bool
        :param email: User email
        :return: True if user has been successfully suspended
        """
        response = self.send_request_and_parse(email, self.SUSPEND_USER_URL)
        return response["Succeeded"]

    def resend_activation_email(self, email):
        """Resend activation email
        :rtype: bool
        :param email: User email
        :return: True if email activation has been successfully sent
        """
        response = self.send_request_and_parse(email, self.RESEND_ACTIVATION_EMAIL_URL)
        return response["Succeeded"]

    # Groups

    def add_group(self, group):
        """Adds a group
        :rtype: dict
        :param group: Group dictionary:
        { 
             "Name": "Group name",
             "OrganizationalUnit": "Org unit" ,
         }
        :return: A dictionary containing:
         { 
             "Succeeded: True,
             "Message": "...",
             "Value": "group guid"
         }
        """
        return self.send_request_and_parse(group, self.ADD_GROUP_URL)

    def delete_group(self, group):
        """Deletes a group
        :rtype: bool
        :param group: Group name
        :return: True if group has been successfully deleted
        """
        response = self.send_request_and_parse(group, self.DELETE_GROUP_URL)
        return response["Succeeded"]

    def assign_group_member(self, group_member):
        """Adds a group member
        :param group_member: Group member dictionary:
        {
             "GroupName": "Group name",
             "MemberName": "user@test.com",
         }
        :return: True if group member has been successfully added
        """
        response = self.send_request_and_parse(group_member, self.ASSIGN_GROUP_MEMBER_URL)
        return response["Succeeded"]

    def unassign_group_member(self, group_member):
        """Deletes a group member
        :param group_member: Group member dictionary:
        { 
             "GroupName": "Group name",
             "MemberName": "user@test.com",
         }
        :return: True if group member has been successfully deleted
        """
        response = self.send_request_and_parse(group_member, self.UNASSIGN_GROUP_MEMBER_URL)
        return response["Succeeded"]

    # Roles

    def post_role(self, role):
        """Updates or creates a role
        :rtype: dict
        :param role: A dictionary: {"Id": "...", "Name": "..."}
        :return: A dictionary containing:
         { "Succeeded": True, "Message": "...", "Value": "Role guid" }
        """
        return self.send_request_and_parse(role, self.POST_ROLE_URL)

    def delete_role(self, role_guid):
        """Deletes a role
        :rtype: dict
        :param role_guid: Role guid
        :return: True is role successfully deleted
        """
        response = self.send_request_and_parse(role_guid, self.DELETE_ROLE_URL)
        return response["Succeeded"]

    def get_assigned_to_role(self, role_guid):
        """Gets assigned items to role
        :rtype: dict
        :param role_guid: Role guid
        :return: A dictionary containing:
        {
            "Succeeded": True,
            "Message": "...",
            "Value": {
                "Users": ["user1@test.com", "user2@test.com"],
                "Groups": ["Group 1", "Group 1"]
            }
        }
        """
        return self.send_request_and_parse(role_guid, self.GET_ASSIGNED_TO_ROLE_URL)

    def assign_to_role(self, role_items):
        """Assigns items to role
        :rtype: dict
        :param role_items: Role items:
        {
             "Code": "Role guid",
             "Users": ["user1@test.com", "user2@test.com"],
             "Groups": ["Group 1", "Group 1"]
        }
        :return: True if items has been successfully added
        """
        response = self.send_request_and_parse(role_items, self.ASSIGN_TO_ROLE_URL)
        return response["Succeeded"]

    def get_roles(self, size):
        """Assigns items to role
        :rtype: dict
        :param size: Size: { "Size": 10, "Offset": 0 }
        :return: A dictionary containing:
         {
             "Succeeded: true,
             "Message": "...",
             "Value": {
                "Total":2,
                "Items": [
                    {"Id":"guid1",Name:"Role 1",Order:1},
                    {"Id":"guid2",Name:"Role 2",Order:2}
                ]
             }
         }
        """
        return self.send_request_and_parse(size, self.GET_ROLES_URL)

    def send_request_and_parse(self, payload, url):
        """Sends a REST post request to NoPassword API, parses null response
        :rtype: dict
        :param payload: request data in json format
        :param url: REST url
        :return: response
        """
        response = self.send_request(payload, url)

        if response is None:
            return {"Succeeded": False}

        if response["Succeeded"] is False:
            print(response["Message"])

        return response

    def send_request(self, payload, url):
        """Sends a REST post request to NoPassword API
        :param payload: Data
        :param url: REST url
        :return: json
        """
        now = str(datetime.utcnow())
        now = now[:19] + "Z"
        payload = json.dumps(payload).encode()
        payload = base64.b64encode(payload).decode()
        signature = self.rsaCipher.sign(now + payload)

        request = {
            "Payload": payload,
            "Timestamp": now,
            "Signature": signature,
            "Key": self.GENERIC_API_KEY
        }
        headers = {"Content-type": self.APPLICATION_JSON}
        response = requests.post(url, json.dumps(request), headers=headers)

        if response.status_code == HTTPStatus.OK.value:
            try:
                jresp = response.json()
            except Exception as err:
                print("json expected:", err)
                print("response =", response.content)
                return None

            if jresp["Succeeded"]:
                enc_key = self.rsaCipher.decrypt(jresp["Value"]["EncKey"])
                enc_key = json.loads(enc_key)
                aes_key = base64.b64decode(enc_key["K"])
                aes_iv = base64.b64decode(enc_key["V"])
                aes_cipher = AESCipher(aes_key, aes_iv, self.UTF_ENCODING)
                payload = aes_cipher.decrypt(jresp["Value"]["Payload"])
                return json.loads(payload)
            else:
                print("error:", jresp["Message"])
                # print("request =", json.dumps(request, indent=4))
                # print("response =", response.content)
                return None

        else:
            print("error:", response.text)

        return None

    def public_key_registration(self, now):
        """Registers the public RSA key in NoPassword. The key is registered just once and can't be overwritten.
        :param now: UTC current time yyyy-mm-dd hh:mi:ss
        :return: True if the key was successfully published. False otherwise.
        """
        now = now[:19] + "Z"
        signature = self.rsaCipher.sign(now + self.trimmed_pub_key)

        request = {
            "Payload": self.trimmed_pub_key,
            "Timestamp": now,
            "Signature": signature,
            "Key": self.GENERIC_API_KEY
        }
        headers = {"Content-type": self.APPLICATION_JSON}
        response = requests.post(self.PUBLIC_KEY_REGISTRATION_URL, json.dumps(request), headers=headers)
        jresp = response.json()

        if response.status_code == HTTPStatus.OK.value and jresp["Succeeded"]:
            print("key updated")
            return True
        else:
            print("key update error:", jresp["Message"])
            print(json.dumps(request))
            return False
