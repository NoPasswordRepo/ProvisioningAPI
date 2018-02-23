package com.nopassword.provisioning.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * This class represents an user
 *
 * @author NoPassword
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class User {

    @JsonProperty("EmployeeID")
    private String employeeID;

    @JsonProperty("Attributes")
    private List<Attribute> attributes;

    @JsonProperty("Description")
    private String description;

    @JsonProperty("Email")
    private String email;

    @JsonProperty("SamAccountName")
    private String samAccountName;

    @JsonProperty("FirstName")
    private String firstName;

    @JsonProperty("PhoneNumber")
    private String phoneNumber;

    @JsonProperty("OU")
    private String ou;

    @JsonProperty("SecondaryEmail")
    private String secondaryEmail;

    @JsonProperty("Department")
    private String department;

    @JsonProperty("LastName")
    private String lastName;

    /**
     * Creates a new user
     */
    public User() {
    }

    /**
     * Creates a new user
     *
     * @param email User principal email
     * @param firstName First name
     * @param lastName Last name
     */
    public User(String email, String firstName, String lastName) {
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
    }

    /**
     * Gets employee id
     *
     * @return Employee id
     */
    public String getEmployeeID() {
        return employeeID;
    }

    /**
     * Sets employee id
     *
     * @param EmployeeID Employee id
     */
    public void setEmployeeID(String EmployeeID) {
        this.employeeID = EmployeeID;
    }

    /**
     * Gets attributes
     *
     * @return Attributes list
     */
    public List<Attribute> getAttributes() {
        return attributes;
    }

    /**
     * Sets attributes
     *
     * @param Attributes Attributes list
     */
    public void setAttributes(List<Attribute> Attributes) {
        this.attributes = Attributes;
    }

    /**
     * Gets description
     *
     * @return Description
     */
    public String getDescription() {
        return description;
    }

    /**
     * Sets Description
     *
     * @param Description Description
     */
    public void setDescription(String Description) {
        this.description = Description;
    }

    /**
     * Gets principal email
     *
     * @return User principal email
     */
    public String getEmail() {
        return email;
    }

    /**
     * Sets principal email
     *
     * @param Email User principal email
     */
    public void setEmail(String Email) {
        this.email = Email;
    }

    /**
     * Gets SamAccountName
     *
     * @return SamAccountName
     */
    public String getSamAccountName() {
        return samAccountName;
    }

    /**
     * Sets SamAccountName
     *
     * @param SamAccountName SamAccountName
     */
    public void setSamAccountName(String SamAccountName) {
        this.samAccountName = SamAccountName;
    }

    /**
     * Gets first name
     *
     * @return First name
     */
    public String getFirstName() {
        return firstName;
    }

    /**
     * Sets first name
     *
     * @param FirstName First name
     */
    public void setFirstName(String FirstName) {
        this.firstName = FirstName;
    }

    /**
     * Gets phone number
     *
     * @return Phone number
     */
    public String getPhoneNumber() {
        return phoneNumber;
    }

    /**
     * Sets phone number
     *
     * @param PhoneNumber Phone number
     */
    public void setPhoneNumber(String PhoneNumber) {
        this.phoneNumber = PhoneNumber;
    }

    /**
     * Gets organizational unit
     *
     * @return
     */
    public String getOU() {
        return ou;
    }

    /**
     * Sets organizational unit
     *
     * @param OU Organizational unit
     */
    public void setOU(String OU) {
        this.ou = OU;
    }

    /**
     * Gets secondary email
     *
     * @return Secondary email
     */
    public String getSecondaryEmail() {
        return secondaryEmail;
    }

    /**
     * Sets secondary email
     *
     * @param SecondaryEmail Secondary email
     */
    public void setSecondaryEmail(String SecondaryEmail) {
        this.secondaryEmail = SecondaryEmail;
    }

    /**
     * Gets department
     *
     * @return Department
     */
    public String getDepartment() {
        return department;
    }

    /**
     * Sets department
     *
     * @param Department Department
     */
    public void setDepartment(String Department) {
        this.department = Department;
    }

    /**
     * Sets last name
     *
     * @return last name
     */
    public String getLastName() {
        return lastName;
    }

    /**
     * Sets last name
     *
     * @param LastName Last name
     */
    public void setLastName(String LastName) {
        this.lastName = LastName;
    }

    @Override
    public String toString() {
        String user
                = "User{EmployeeID = " + employeeID
                + ", Description = " + description
                + ", Email = " + email
                + ", SamAccountName = " + samAccountName
                + ", FirstName = " + firstName
                + ", PhoneNumber = " + phoneNumber
                + ", OU = " + ou
                + ", SecondaryEmail = " + secondaryEmail
                + ", Department = " + department
                + ", LastName = " + lastName
                + ", Attributes = [";

        if (attributes != null) {
            for (Attribute a : attributes) {
                user += a + ",";
            }
        }
        user += "]}";
        return user;
    }

    /**
     * Represents a user attribute
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public class Attribute {

        @JsonProperty("Name")
        private String name;

        @JsonProperty("Value")
        private String value;

        /**
         * Creates a new empty attribute
         */
        public Attribute() {
        }

        /**
         * Creates a new attribute
         *
         * @param name Name
         * @param value Value
         */
        public Attribute(String name, String value) {
            this.name = name;
            this.value = value;
        }

        /**
         * Gets attribute name
         *
         * @return Attribute name
         */
        public String getName() {
            return name;
        }

        /**
         * Sets attribute name
         *
         * @param Name Attribute name
         */
        public void setName(String Name) {
            this.name = Name;
        }

        /**
         * Gets attribute value
         *
         * @return Attribute value
         */
        public String getValue() {
            return value;
        }

        /**
         * Sets attribute value
         *
         * @param Value Attribute value
         */
        public void setValue(String Value) {
            this.value = Value;
        }

        @Override
        public String toString() {
            return "Attribute{Name = " + name + ", Value = " + value + "}";
        }
    }

}
