package com.nopassword.provisioning;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nopassword.common.crypto.RSACipher;
import com.nopassword.common.crypto.RSAKeyLoader;
import com.nopassword.common.model.GenericRequest;
import com.nopassword.common.model.GenericResponse;
import com.nopassword.common.utils.GenericResponseHandler;
import com.nopassword.common.utils.RestClient;
import com.nopassword.provisioning.model.ProvisioningResponse;
import com.nopassword.provisioning.model.User;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import java.util.Properties;
import org.apache.log4j.Logger;

/**
 * Consumes NoPassword provisioning API services
 *
 * @author NoPassword
 */
public class UsersProvisioning {

    private static final Logger LOG = Logger.getLogger(UsersProvisioning.class);

    private static String BASE_URL;
    private static String ADD_USER_URL;
    private static String EDIT_USER_URL;
    private static String DELETE_USER_URL;
    private static String SUSPEND_USER_URL;
    private static String RESEND_ACTIVATION_EMAIL_URL;
    private static String PUBLIC_KEY_REGISTRATION_URL;
    private static String IS_USER_EXISTS_URL;
    private static String ADD_GROUP_URL;
    private static String DELETE_GROUP_URL;
    private static String ASSIGN_GROUP_MEMBER_URL;
    private static String UNASSIGN_GROUP_MEMBER_URL;
    private static String POST_ROLE_URL;
    private static String GET_ROLES_URL;
    private static String DELETE_ROLE_URL;
    private static String ASSIGN_TO_ROLE_URL;
    private static String GET_ASSIGNED_TO_ROLE_URL;

    private final RSACipher rsaCipher;
    private final String genericAPIKey;

    /**
     * Creates a UsersProvisioning object
     *
     * @param publicKeyFile Path to RSA public key file
     * @param privateKeyFile Path to RSA private key file in PKCS8 format
     * @throws Exception
     */
    public UsersProvisioning(String publicKeyFile, String privateKeyFile) throws Exception {
        PublicKey publicKey = RSAKeyLoader.loadPublicKey(publicKeyFile);
        PrivateKey privateKey = RSAKeyLoader.loadPrivateKey(privateKeyFile);
        this.rsaCipher = new RSACipher(publicKey, privateKey, StandardCharsets.UTF_16LE);

        Properties props = new Properties();
        props.load(UsersProvisioning.class.getResourceAsStream("/conf/config.properties"));
        this.genericAPIKey = props.getProperty("generic_api_key");

        BASE_URL = props.getProperty("provisioning_url");
        ADD_USER_URL = BASE_URL + "AddUser";
        EDIT_USER_URL = BASE_URL + "EditUser";
        DELETE_USER_URL = BASE_URL + "DeleteUser";
        SUSPEND_USER_URL = BASE_URL + "SuspendUser";
        RESEND_ACTIVATION_EMAIL_URL = BASE_URL + "ResendActivationEmail";
        PUBLIC_KEY_REGISTRATION_URL = BASE_URL + "PKReg";
        IS_USER_EXISTS_URL = BASE_URL + "IsUserExist";
        ADD_GROUP_URL = BASE_URL + "AddGroup";
        DELETE_GROUP_URL = BASE_URL + "DeleteGroup";
        ASSIGN_GROUP_MEMBER_URL = BASE_URL + "AssignGroupMember";
        UNASSIGN_GROUP_MEMBER_URL = BASE_URL + "UnassignGroupMember";
        POST_ROLE_URL = BASE_URL + "PostRole";
        GET_ROLES_URL = BASE_URL + "GetRoles";
        DELETE_ROLE_URL = BASE_URL + "DeleteRole";
        ASSIGN_TO_ROLE_URL = BASE_URL + "AssignToRole";
        GET_ASSIGNED_TO_ROLE_URL = BASE_URL + "GetAssignedToRole";
    }

    /**
     * Checks if user exists
     *
     * @param email User email
     * @return True if user exists
     */
    public boolean isUserExists(String email) {
        Map<String, Object> response = sendRequestAndParse(email, IS_USER_EXISTS_URL);
        return (boolean) response.get(ProvisioningResponse.SUCCEEDED);
    }

    /**
     * Adds user
     *
     * @param user User
     * @return True if user has been successfully added
     */
    public boolean addUser(User user) {
        Map<String, Object> response = sendRequestAndParse(user, ADD_USER_URL);
        return (boolean) response.get(ProvisioningResponse.SUCCEEDED);
    }

    /**
     * Edits user
     *
     * @param user User
     * @return True if user has been successfully edited
     */
    public boolean editUser(User user) {
        Map<String, Object> response = sendRequestAndParse(user, EDIT_USER_URL);
        return (boolean) response.get(ProvisioningResponse.SUCCEEDED);
    }

    /**
     * Suspends an user
     *
     * @param email User email
     * @return True if user has been successfully suspended
     */
    public boolean suspendUser(String email) {
        Map<String, Object> response = sendRequestAndParse(email, SUSPEND_USER_URL);
        return (boolean) response.get(ProvisioningResponse.SUCCEEDED);
    }

    /**
     * Deletes a user
     *
     * @param email User email
     * @return True if user has been successfully deleted
     */
    public boolean deleteUser(String email) {
        Map<String, Object> response = sendRequestAndParse(email, DELETE_USER_URL);
        return (boolean) response.get(ProvisioningResponse.SUCCEEDED);
    }

    /**
     * Resends activation email
     *
     * @param email User email
     * @return True if user has been successfully sent
     */
    public boolean resendActivationEmail(String email) {
        Map<String, Object> response = sendRequestAndParse(email, RESEND_ACTIVATION_EMAIL_URL);
        return (boolean) response.get(ProvisioningResponse.SUCCEEDED);
    }

    /**
     * Adds group
     *
     * @param group Group with following the attributes: { "Name": "Group name",
     * "OrganizationalUnit": "Org unit" , }
     * @return Group guid
     */
    public String addGroup(Map group) {
        return (String) sendRequestAndParse(group, ADD_GROUP_URL, String.class);
    }

    /**
     * Deletes a group
     *
     * @param group Group name
     * @return True if group has been successfully deleted
     */
    public boolean deleteGroup(String group) {
        Map<String, Object> response = sendRequestAndParse(group, DELETE_GROUP_URL);
        return (boolean) response.get(ProvisioningResponse.SUCCEEDED);
    }

    /**
     * Assigns a group member
     *
     * @param groupMember Group member with the following attributes: {
     * "GroupName": "Group name", "MemberName": "user@test.com" }
     * @return True if group member has been successfully added
     */
    public boolean assignGroupMember(Map groupMember) {
        Map<String, Object> response = sendRequestAndParse(groupMember, ASSIGN_GROUP_MEMBER_URL);
        return (boolean) response.get(ProvisioningResponse.SUCCEEDED);
    }

    /**
     * Deletes a group member
     *
     * @param groupMember Group member with the following attributes: {
     * "GroupName": "Group name", "MemberName": "user@test.com", }
     * @return True if group member has been successfully deleted
     */
    public boolean unassignGroup(Map groupMember) {
        Map<String, Object> response = sendRequestAndParse(groupMember, UNASSIGN_GROUP_MEMBER_URL);
        return (boolean) response.get(ProvisioningResponse.SUCCEEDED);
    }

    /**
     * Updates or creates a role
     *
     * @param role Role with the following attributes: {"Id": "...", "Name":
     * "..."}
     * @return Role guid
     */
    public String postRole(Map role) {
        return sendRequestAndParse(role, POST_ROLE_URL, String.class);
    }

    /**
     * Deletes a role
     *
     * @param roleGUID Role guid
     * @return True is role successfully deleted
     */
    public boolean deleteRole(String roleGUID) {
        Map<String, Object> response = sendRequestAndParse(roleGUID, DELETE_ROLE_URL);
        return (boolean) response.get(ProvisioningResponse.SUCCEEDED);
    }

    /**
     * Gets assigned items to role
     *
     * @param roleGUID Role guid
     * @return A map containing users and groups: { "Users": ["user1@test.com",
     * "user2@test.com"], "Groups": ["Group 1", "Group 1"] }
     */
    public Map getAssignedToRole(String roleGUID) {
        return (Map) sendRequestAndParse(roleGUID, GET_ASSIGNED_TO_ROLE_URL);
    }

    /**
     * Assigns items to role
     *
     * @param roleItems Role items with the following attributes: { "Code":
     * "Role guid", "Users": ["user1@test.com", "user2@test.com"], "Groups":
     * ["Group 1", "Group 1"] }
     * @return True if items has been successfully added
     */
    public boolean assignToRole(Map roleItems) {
        return (boolean) sendRequestAndParse(roleItems, ASSIGN_TO_ROLE_URL).get(ProvisioningResponse.SUCCEEDED);
    }

    /**
     * Assigns items to role
     *
     * @param size Maximum number of roles to be returned, it must contain the
     * following attributes { "Size": 10, "Offset": 0 }
     * @return A map containing the following attributes: { "Total":2, "Items":
     * [ {"Id":"guid1",Name:"Role 1",Order:1}, {"Id":"guid2",Name:"Role
     * 2",Order:2} ] }
     */
    public Map getRoles(Map size) {
        return (Map) sendRequestAndParse(size, GET_ROLES_URL);
    }
    
    /**
     * 
     * @param payload Data
     * @param url Request URL
     * @return A map containing result values
     */
    public Map<String, Object> sendRequestAndParse(Object payload, String url) {
        return sendRequestAndParse(payload, url, Map.class);
    }

    /**
     * Sends a REST post request to NoPassword API, parses null response
     *
     * @param <T> 
     * @param payload Data
     * @param url Request URL
     * @param clazz Specifies return type
     * @return Object instance of type T
     */
    public <T> T sendRequestAndParse(Object payload, String url, Class<T> clazz) {
        try {
            GenericRequest request = new GenericRequest(genericAPIKey, payload, rsaCipher);
            RestClient client = new RestClient();
            GenericResponse response = client.post(url, request, GenericResponse.class);
            return GenericResponseHandler.parseGenericResponse(response, rsaCipher, clazz);
        } catch (JsonProcessingException ex) {
            LOG.error("Creating generic request", ex);
        } catch (IOException ex) {
            LOG.error("Error parsing generic response", ex);
        }
        return null;
    }

}
