package com.nopassword.provisioning.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Represents a request to NoPassword provisioning services
 *
 * @author NoPassword
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ProvisioningRequest {

    @JsonProperty("Payload")
    private String payload;

    @JsonProperty("Timestamp")
    private String timestamp;

    @JsonProperty("Signature")
    private String signature;

    @JsonProperty("Key")
    private String key;

    /**
     * Creates a new request object
     *
     * @param payload Data
     * @param timestamp Current UTC time
     * @param signature Signed timestamp and payload
     * @param key Generic API key
     */
    public ProvisioningRequest(String payload, String timestamp, String signature, String key) {
        this.payload = payload;
        this.timestamp = timestamp;
        this.signature = signature;
        this.key = key;
    }

    /**
     * Gets payload
     *
     * @return Payload
     */
    public String getPayload() {
        return payload;
    }

    /**
     * Sets payload
     *
     * @param payload Payload
     */
    public void setPayload(String payload) {
        this.payload = payload;
    }

    /**
     * Gets timestamp
     *
     * @return Timestamp in UTC format yyyy-mm-dd hh:mi:ssZ
     */
    public String getTimestamp() {
        return timestamp;
    }

    /**
     * Sets timestamp
     *
     * @param timestamp Timestamp in UTC format yyyy-mm-dd hh:mi:ssZ
     */
    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    /**
     * Gets signature
     *
     * @return Signature
     */
    public String getSignature() {
        return signature;
    }

    /**
     * Sets signature
     *
     * @param signature RSA signed timestamp and payload
     */
    public void setSignature(String signature) {
        this.signature = signature;
    }

    /**
     * Gets generic API key
     *
     * @return Generic API key
     */
    public String getKey() {
        return key;
    }

    /**
     * Sets generic API key
     *
     * @param key Generic API key
     */
    public void setKey(String key) {
        this.key = key;
    }

    @Override
    public String toString() {
        return "ProvisioningRequest{" + "payload=" + payload
                + ", timestamp=" + timestamp
                + ", signature=" + signature
                + ", key=" + key + '}';
    }

}
