package com.nopassword.provisioning;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nopassword.common.crypto.NPCipher;
import com.nopassword.common.crypto.RSAKeyLoader;
import com.nopassword.provisioning.model.ProvisioningRequest;
import com.nopassword.provisioning.model.ProvisioningResponse;
import com.nopassword.provisioning.model.User;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.springframework.web.client.RestTemplate;

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

    private final NPCipher rsaCipher;
    private final String trimmedPublicKey;
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
        this.rsaCipher = new NPCipher(publicKey, privateKey, StandardCharsets.UTF_16LE);
        this.trimmedPublicKey = new String(Files.readAllBytes(Paths.get(publicKeyFile)))
                .replaceAll("\n", "")
                .replaceAll("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll("-----END PUBLIC KEY-----", "");

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
        return (String) sendRequestAndParse(group, ADD_GROUP_URL).get("Value");
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
        Map<String, Object> response = sendRequestAndParse(role, POST_ROLE_URL);
        return (String) response.get("Value");
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
        return (Map) sendRequestAndParse(roleGUID, GET_ASSIGNED_TO_ROLE_URL).get("Value");
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
        return (Map) sendRequestAndParse(size, GET_ROLES_URL).get("Value");
    }

    /**
     * Sends a REST post request to NoPassword API, parses null response
     *
     * @param payload Data
     * @param url Request URL
     * @return Map
     */
    public Map<String, Object> sendRequestAndParse(Object payload, String url) {
        Map<String, Object> response = null;
        try {
            response = sendRequest(payload, url);
        } catch (Exception ex) {
            LOG.error("error procesing request", ex);
        }

        if (response == null) {
            response = new HashMap();
            response.put(ProvisioningResponse.SUCCEEDED, false);
            return response;
        }
        return response;
    }

    /**
     *
     * @param payload Data
     * @param url REST service url
     * @return A map containing service response
     * @throws Exception
     */
    public Map sendRequest(Object payload, String url) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        String timestamp = currentTime();
        String jsonPayload = mapper.writeValueAsString(payload);
        jsonPayload = Base64.getEncoder().encodeToString(jsonPayload.getBytes());
        String signature = rsaCipher.sign(timestamp + jsonPayload);
        ProvisioningRequest request;
        Map<String, Object> result = null;

        request = new ProvisioningRequest(
                jsonPayload, timestamp, signature, genericAPIKey);

        RestTemplate client = new RestTemplate();
        ProvisioningResponse response = client.postForObject(url, request, ProvisioningResponse.class);

        if (response == null) {
            return null;
        }

        if (response.succeeded()) {
            //retrieve and decrypt AES key and iv
            String encKeyString = rsaCipher.decrypt(response.getValue().getEncKey());
            Map<String, String> encKey = mapper.readValue(encKeyString, Map.class);
            byte[] aesKey = Base64.getDecoder().decode(encKey.get("K"));
            byte[] aesIV = Base64.getDecoder().decode(encKey.get("V"));

            //decrypt payload with AES
            String respPayload = (String) response.getValue().getPayload();
            NPCipher aesCipher = new NPCipher(aesKey, aesIV, StandardCharsets.UTF_16LE);
            result = mapper.readValue(aesCipher.decrypt(respPayload), Map.class);
        } else {
            LOG.error(response.getMessage());
            return null;
        }

        if (!(boolean) result.get("Succeeded")) {
            LOG.error(result.get("Message"));
        }
        return result;
    }

    /**
     * Registers the public RSA key in NoPassword. The key is registered just
     * once and can't be overwritten.
     *
     * @return True if the key was successfully published. False otherwise.
     */
    public boolean publicKeyRegistration() {
        String timestamp = currentTime();
        String signature = timestamp + trimmedPublicKey;
        ProvisioningRequest request
                = new ProvisioningRequest(trimmedPublicKey,
                        timestamp, signature, genericAPIKey);
        RestTemplate client = new RestTemplate();
        ProvisioningResponse response;

        try {
            response = client.postForObject(PUBLIC_KEY_REGISTRATION_URL,
                    request, ProvisioningResponse.class);
        } catch (Exception ex) {
            LOG.error("error registering key", ex);
            return false;
        }

        if (!response.succeeded()) {
            LOG.error(response.getMessage());
        }

        return response.succeeded();
    }

    /**
     * Gets UTC
     *
     * @return UTC current time yyyy-mm-dd hh:mi:ssZ
     */
    public static String currentTime() {
        return ZonedDateTime.now(ZoneOffset.UTC).toString().substring(0, 19).replace("T", " ") + "Z";
    }

}
