package com.nopassword.provisioning;

import com.nopassword.provisioning.model.User;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.log4j.PropertyConfigurator;

/**
 * A sample that shows how to use UsersProvisioning class
 *
 * @author NoPassword
 */
public class UsersProvisioningSample {

    /**
     *
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        PropertyConfigurator.configure(UsersProvisioningSample.class.getResource("/conf/log4j.properties").getPath());
        String publicKey = UsersProvisioningSample.class.getResource("/conf/public_key.pem").getPath();
        String privateKey = UsersProvisioningSample.class.getResource("/conf/private_key_pkcs8.pem").getPath();
        UsersProvisioning provisioning = new UsersProvisioning(publicKey, privateKey);

        System.out.println("public key registration (run just once)");
        System.out.println(provisioning.publicKeyRegistration());
        User user = new User("john.smith@example.com", "John", "Smith");

        //group sample
        Map<String, String> group = new HashMap<>();
        group.put("Name", "TEST GROUP");
        group.put("OrganizationalUnit", "Org unit");

        //group member sample
        Map<String, String> groupMember = new HashMap<>();
        groupMember.put("GroupName", group.get("Name"));
        groupMember.put("MemberName", user.getEmail());

        //role sample
        Map<String, String> role = new HashMap<>();
        role.put("Id", "Test Role x");
        role.put("Name", "Test Role x");

        System.out.println("\nadd/edit user");
        if (provisioning.isUserExists(user.getEmail())) {
            if (provisioning.editUser(user)) {
                System.out.println("user edited");
            }
        } else {
            if (provisioning.addUser(user)) {
                System.out.println("user added");
            }
        }

        System.out.println("\nadd group");
        String groupId = provisioning.addGroup(group);
        System.out.println("group added: " + groupId);

        System.out.println("\nadd group member");
        if (provisioning.assignGroupMember(groupMember)) {
            System.out.println("group member assigned");
        }

        System.out.println("\nresend activation email");
        if (provisioning.resendActivationEmail(user.getEmail())) {
            System.out.println("activation email has been sent");
        }

        System.out.println("\nadd role");
        String roleId = provisioning.postRole(role);
        System.out.println("role added: " + roleId);

        System.out.println("\nadd items to role");
        Map<String, Object> roleItems = new HashMap<>();
        roleItems.put("Code", roleId);
        roleItems.put("Users", new String[]{user.getEmail()});
        roleItems.put("Groups", new String[]{group.get("Name")});

        if (provisioning.assignToRole(roleItems)) {
            System.out.println("role items assigned");
        }

        System.out.println("\nget roles");
        Map<String, Integer> size = new HashMap<>();
        size.put("Size", 100);
        size.put("Offset", 0);
        System.out.println(provisioning.getRoles(size));

        System.out.println("\nget role items");
        Map<String, List<String>> items = provisioning.getAssignedToRole(roleId);
        System.out.print("Users: ");
        items.get("Users").forEach((u) -> {
            System.out.print(u + " ");
        });
        System.out.print("\nGroups: ");
        items.get("Groups").forEach((g) -> {
            System.out.print(g + " ");
        });

        System.out.println("\n\ndelete role");
        if (provisioning.deleteRole(roleId)) {
            System.out.println("role deleted");
        }

        System.out.println("\nsuspend user");
        if (provisioning.suspendUser(user.getEmail())) {
            System.out.println("user suspended");
        }

        System.out.println("\ndelete group member");
        if (provisioning.unassignGroup(groupMember)) {
            System.out.println("group member deleted");
        }

        System.out.println("\ndelete group");
        if (provisioning.deleteGroup(group.get("Name"))) {
            System.out.println("group deleted");
        }

        System.out.println("\ndelete user");
        if (provisioning.deleteUser(user.getEmail())) {
            System.out.println("user deleted");
        }
    }
}
