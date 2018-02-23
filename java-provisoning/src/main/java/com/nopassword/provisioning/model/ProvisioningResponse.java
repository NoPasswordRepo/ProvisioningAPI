package com.nopassword.provisioning.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Represents a provisioning service response
 *
 * @author NoPassword
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ProvisioningResponse {

    public static final String SUCCEEDED = "Succeeded";

    @JsonProperty("Message")
    private String message;

    @JsonProperty("Succeeded")
    private boolean succeeded;

    @JsonProperty("Value")
    private Value value;

    /**
     * Gets response message
     *
     * @return Message
     */
    public String getMessage() {
        return message;
    }

    /**
     * Sets response message
     *
     * @param message Message
     */
    public void setMessage(String message) {
        this.message = message;
    }

    /**
     * Gets response success state
     *
     * @return True is successful
     */
    public boolean succeeded() {
        return succeeded;
    }

    /**
     * Sets response success state
     *
     * @param succeeded True if successful
     */
    public void succeeded(boolean succeeded) {
        this.succeeded = succeeded;
    }

    /**
     * Gets response value
     *
     * @return Response value
     */
    public Value getValue() {
        return value;
    }

    /**
     * Sets response value
     *
     * @param value Response value
     */
    public void setValue(Value value) {
        this.value = value;
    }

    /**
     * Contains AES keys and encrypted payload
     */
    public class Value {

        @JsonProperty("EncKey")
        private String encKey;

        @JsonProperty("Payload")
        private String payload;

        @JsonProperty("Success")
        private boolean success;

        /**
         * Gets base64 encoded AES keys
         *
         * @return Base64 encoded AES keys
         */
        public String getEncKey() {
            return encKey;
        }

        /**
         * Sets base64 encoded AES keys
         *
         * @param encKey Base64 encoded AES keys
         */
        public void setEncKey(String encKey) {
            this.encKey = encKey;
        }

        /**
         * Gets encrypted payload. Must be decrypted with RSA.
         *
         * @return Encrypted payload
         */
        public String getPayload() {
            return payload;
        }

        /**
         * Sets RSA encrypted payload
         *
         * @param payload RSA encrypted payload
         */
        public void setPayload(String payload) {
            this.payload = payload;
        }

        /**
         * Gets request operation success state
         *
         * @return True if successful
         */
        public boolean isSuccess() {
            return success;
        }

        /**
         * Sets request operation success state
         *
         * @param success True if successful
         */
        public void setSuccess(boolean success) {
            this.success = success;
        }

    }

}
