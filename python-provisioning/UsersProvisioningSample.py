# An example about how to use user provisioning API
from _datetime import datetime

from UsersProvisioning import UsersProvisioning

f = open("/home/migue/cert/public_key.pem", "r")
pub_key = f.read()
f.close()
f = open("/home/migue/cert/private_key.pem", "r")
priv_key = f.read()
f.close()

# User dictionary sample
user = {
    "Email": "john.smith@example.com",
    "SecondaryEmail": "john@example.com",
    "FirstName": "John",
    "LastName": "Smith",
    "PhoneNumber": "(111) 222-33-44"
}

# Group dictionary sample
group = {
    "Name": "TEST GROUP",
    "OrganizationalUnit": "Org unit",
}

# Group member dictionary sample
group_member = {
    "GroupName": group["Name"],
    "MemberName": user["Email"]
}

# Role sample
role = {
    "Id": "TEST ROLE1",
    "Name": "TEST ROLE1"
}

now = str(datetime.utcnow())
provisioning = UsersProvisioning(pub_key, priv_key)
print("publish key (run just once)")
provisioning.public_key_registration(now)

print("\nadd/edit user")
if provisioning.is_user_exists(user["Email"]):
    if provisioning.edit_user(user):
        print("user edited")
else:
    if provisioning.add_user(user):
        print("user added")

print("\nadd group")
result = provisioning.add_group(group)
if result["Succeeded"]:
    print("group added", result["Value"])

print("\nadd group member")
if provisioning.assign_group_member(group_member):
    print("group member added")

print("\nresend activation email")
if provisioning.resend_activation_email(user["Email"]):
    print("activation email has been sent")

print("\nadd role")
post_role = provisioning.post_role(role)
role_guid = post_role["Value"]
if post_role["Succeeded"]:
    print("role added", role_guid)

print("\nadd items to role")
role_items = {
    "Code": role_guid,
    "Users": [user["Email"]],
    "Groups": [group["Name"]]
}
if provisioning.assign_to_role(role_items):
    print("role items added")

print("\nget roles")
size = {
    "Size": 100,
    "Offset": 0
}
roles = provisioning.get_roles(size)
if roles["Succeeded"]:
    print(roles["Value"]["Items"])

print("\nget role items")
result = provisioning.get_assigned_to_role(role_guid)
if result["Succeeded"]:
    print("Users:", result["Value"]["Users"])
    print("Groups:", result["Value"]["Groups"])

print("\ndelete role")
if provisioning.delete_role(role_guid):
    print("role deleted successfully")

print("\nsuspend user")
if provisioning.suspend_user(user["Email"]):
    print("user suspended")

print("\ndelete group member")
if provisioning.unassign_group_member(group_member):
    print("group member deleted")

print("\ndelete group")
if provisioning.delete_group(group["Name"]):
    print("group deleted")

print("\ndelete user")
if provisioning.delete_user(user["Email"]):
    print("user deleted")
