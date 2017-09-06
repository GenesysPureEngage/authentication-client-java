/*
 * Authentication API
 * Authentication API
 *
 * OpenAPI spec version: 9.0.000.00.764
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.genesys.internal.authentication.model;

import java.util.Objects;
import com.genesys.internal.authentication.model.UserRole;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.io.IOException;

/**
 * This class describes the user in the system. Applicable to different entities (contact-center level user, application/service, cloud system admin)
 */
@ApiModel(description = "This class describes the user in the system. Applicable to different entities (contact-center level user, application/service, cloud system admin)")
@javax.annotation.Generated(value = "io.swagger.codegen.languages.JavaClientCodegen", date = "2017-09-06T22:04:15.668Z")
public class CloudUserDetails {
  @SerializedName("authorities")
  private UserRole authorities = null;

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

  @SerializedName("username")
  private String username = null;

  public CloudUserDetails authorities(UserRole authorities) {
    this.authorities = authorities;
    return this;
  }

   /**
   * Authorities assigned to user
   * @return authorities
  **/
  @ApiModelProperty(required = true, value = "Authorities assigned to user")
  public UserRole getAuthorities() {
    return authorities;
  }

  public void setAuthorities(UserRole authorities) {
    this.authorities = authorities;
  }

  public CloudUserDetails cmeUserName(String cmeUserName) {
    this.cmeUserName = cmeUserName;
    return this;
  }

   /**
   * The user name in CME. Not set for users which are not in CME (applications, cloud system admin,...)
   * @return cmeUserName
  **/
  @ApiModelProperty(value = "The user name in CME. Not set for users which are not in CME (applications, cloud system admin,...)")
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
   * Id of contact center user belongs to (if any)
   * @return contactCenterId
  **/
  @ApiModelProperty(value = "Id of contact center user belongs to (if any)")
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
   * DBID of user record in corresponding CME (present iff user belongs to contact center)
   * @return dbid
  **/
  @ApiModelProperty(value = "DBID of user record in corresponding CME (present iff user belongs to contact center)")
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
   * Id of genesys environment user belongs to (if any)
   * @return environmentId
  **/
  @ApiModelProperty(value = "Id of genesys environment user belongs to (if any)")
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
   * The user name in CME. Not set for users which are not in CME (applications, cloud system admin,...)
   * @return loginName
  **/
  @ApiModelProperty(value = "The user name in CME. Not set for users which are not in CME (applications, cloud system admin,...)")
  public String getLoginName() {
    return loginName;
  }

  public void setLoginName(String loginName) {
    this.loginName = loginName;
  }

  public CloudUserDetails username(String username) {
    this.username = username;
    return this;
  }

   /**
   * System-wide-unique name of user in the system. For contact-center user it includes CME userName , dbid in CME and cc id. For Non-cme users, this can have other formats
   * @return username
  **/
  @ApiModelProperty(required = true, value = "System-wide-unique name of user in the system. For contact-center user it includes CME userName , dbid in CME and cc id. For Non-cme users, this can have other formats")
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
        Objects.equals(this.username, cloudUserDetails.username);
  }

  @Override
  public int hashCode() {
    return Objects.hash(authorities, cmeUserName, contactCenterId, dbid, environmentId, loginName, username);
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
