/*
 * Authentication API
 * Authentication API
 *
 * OpenAPI spec version: 9.0.000.39.1782
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.genesys.internal.authentication.model;

import java.util.Objects;
import java.util.Arrays;
import com.genesys.internal.authentication.model.UserRole;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class describes the user in the system. Applicable to different entities (contact-center level user, application/service, cloud system admin)
 */
@ApiModel(description = "This class describes the user in the system. Applicable to different entities (contact-center level user, application/service, cloud system admin)")
@javax.annotation.Generated(value = "io.swagger.codegen.languages.JavaClientCodegen", date = "2019-06-20T13:34:26.168Z")
public class CloudUserDetails {
  @SerializedName("authorities")
  private List<UserRole> authorities = new ArrayList<UserRole>();

  @SerializedName("cmeUserName")
  private String cmeUserName = null;

  @SerializedName("contactCenterId")
  private String contactCenterId = null;

  @SerializedName("dbid")
  private Integer dbid = null;

  @SerializedName("environmentId")
  private String environmentId = null;

  @SerializedName("loginName")
  private String loginName = null;

  @SerializedName("properties")
  private Map<String, String> properties = null;

  @SerializedName("username")
  private String username = null;

  public CloudUserDetails authorities(List<UserRole> authorities) {
    this.authorities = authorities;
    return this;
  }

  public CloudUserDetails addAuthoritiesItem(UserRole authoritiesItem) {
    this.authorities.add(authoritiesItem);
    return this;
  }

   /**
   * Authorities assigned to the user.
   * @return authorities
  **/
  @ApiModelProperty(required = true, value = "Authorities assigned to the user.")
  public List<UserRole> getAuthorities() {
    return authorities;
  }

  public void setAuthorities(List<UserRole> authorities) {
    this.authorities = authorities;
  }

  public CloudUserDetails cmeUserName(String cmeUserName) {
    this.cmeUserName = cmeUserName;
    return this;
  }

   /**
   * The username in Configuration Server. This property is not set for users who aren&#39;t in Configuration Server (for example, applications/services, cloud system admin and so on.)
   * @return cmeUserName
  **/
  @ApiModelProperty(value = "The username in Configuration Server. This property is not set for users who aren't in Configuration Server (for example, applications/services, cloud system admin and so on.)")
  public String getCmeUserName() {
    return cmeUserName;
  }

  public void setCmeUserName(String cmeUserName) {
    this.cmeUserName = cmeUserName;
  }

  public CloudUserDetails contactCenterId(String contactCenterId) {
    this.contactCenterId = contactCenterId;
    return this;
  }

   /**
   * The ID of the contact center the user belongs to (if any).
   * @return contactCenterId
  **/
  @ApiModelProperty(value = "The ID of the contact center the user belongs to (if any).")
  public String getContactCenterId() {
    return contactCenterId;
  }

  public void setContactCenterId(String contactCenterId) {
    this.contactCenterId = contactCenterId;
  }

  public CloudUserDetails dbid(Integer dbid) {
    this.dbid = dbid;
    return this;
  }

   /**
   * The DBID of the corresponding user record in Configuration Server. This is present if the user belongs to a contact center.
   * @return dbid
  **/
  @ApiModelProperty(value = "The DBID of the corresponding user record in Configuration Server. This is present if the user belongs to a contact center.")
  public Integer getDbid() {
    return dbid;
  }

  public void setDbid(Integer dbid) {
    this.dbid = dbid;
  }

  public CloudUserDetails environmentId(String environmentId) {
    this.environmentId = environmentId;
    return this;
  }

   /**
   * The ID of the Genesys environment the user belongs to (if any).
   * @return environmentId
  **/
  @ApiModelProperty(value = "The ID of the Genesys environment the user belongs to (if any).")
  public String getEnvironmentId() {
    return environmentId;
  }

  public void setEnvironmentId(String environmentId) {
    this.environmentId = environmentId;
  }

  public CloudUserDetails loginName(String loginName) {
    this.loginName = loginName;
    return this;
  }

   /**
   * The username in Configuration Server. This property is not set for users who aren&#39;t in Configuration Server (for example, applications/services, cloud system admin and so on.)
   * @return loginName
  **/
  @ApiModelProperty(value = "The username in Configuration Server. This property is not set for users who aren't in Configuration Server (for example, applications/services, cloud system admin and so on.)")
  public String getLoginName() {
    return loginName;
  }

  public void setLoginName(String loginName) {
    this.loginName = loginName;
  }

  public CloudUserDetails properties(Map<String, String> properties) {
    this.properties = properties;
    return this;
  }

  public CloudUserDetails putPropertiesItem(String key, String propertiesItem) {
    if (this.properties == null) {
      this.properties = new HashMap<String, String>();
    }
    this.properties.put(key, propertiesItem);
    return this;
  }

   /**
   * The user&#39;s properties
   * @return properties
  **/
  @ApiModelProperty(value = "The user's properties")
  public Map<String, String> getProperties() {
    return properties;
  }

  public void setProperties(Map<String, String> properties) {
    this.properties = properties;
  }

  public CloudUserDetails username(String username) {
    this.username = username;
    return this;
  }

   /**
   * The system-wide unique name of the user. For contact center users, this includes the userName in Configuration Server, the DBID in Configuration Server and the contact center ID. For non-Configuration Server users the username can have other formats.
   * @return username
  **/
  @ApiModelProperty(required = true, value = "The system-wide unique name of the user. For contact center users, this includes the userName in Configuration Server, the DBID in Configuration Server and the contact center ID. For non-Configuration Server users the username can have other formats.")
  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    CloudUserDetails cloudUserDetails = (CloudUserDetails) o;
    return Objects.equals(this.authorities, cloudUserDetails.authorities) &&
        Objects.equals(this.cmeUserName, cloudUserDetails.cmeUserName) &&
        Objects.equals(this.contactCenterId, cloudUserDetails.contactCenterId) &&
        Objects.equals(this.dbid, cloudUserDetails.dbid) &&
        Objects.equals(this.environmentId, cloudUserDetails.environmentId) &&
        Objects.equals(this.loginName, cloudUserDetails.loginName) &&
        Objects.equals(this.properties, cloudUserDetails.properties) &&
        Objects.equals(this.username, cloudUserDetails.username);
  }

  @Override
  public int hashCode() {
    return Objects.hash(authorities, cmeUserName, contactCenterId, dbid, environmentId, loginName, properties, username);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class CloudUserDetails {\n");
    
    sb.append("    authorities: ").append(toIndentedString(authorities)).append("\n");
    sb.append("    cmeUserName: ").append(toIndentedString(cmeUserName)).append("\n");
    sb.append("    contactCenterId: ").append(toIndentedString(contactCenterId)).append("\n");
    sb.append("    dbid: ").append(toIndentedString(dbid)).append("\n");
    sb.append("    environmentId: ").append(toIndentedString(environmentId)).append("\n");
    sb.append("    loginName: ").append(toIndentedString(loginName)).append("\n");
    sb.append("    properties: ").append(toIndentedString(properties)).append("\n");
    sb.append("    username: ").append(toIndentedString(username)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(java.lang.Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }

}

