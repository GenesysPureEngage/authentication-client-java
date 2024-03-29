/*
 * Authentication API
 * Authentication API
 *
 * OpenAPI spec version: 9.0.000.68.2560
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.genesys.internal.authentication.model;

import java.util.Objects;
import java.util.Arrays;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.io.IOException;

/**
 * AuthSchemeLookupData
 */
@javax.annotation.Generated(value = "io.swagger.codegen.languages.JavaClientCodegen", date = "2022-03-03T19:44:00.986Z")
public class AuthSchemeLookupData {
  @SerializedName("tenant")
  private String tenant = null;

  @SerializedName("userName")
  private String userName = null;

  public AuthSchemeLookupData tenant(String tenant) {
    this.tenant = tenant;
    return this;
  }

   /**
   * Get tenant
   * @return tenant
  **/
  @ApiModelProperty(value = "")
  public String getTenant() {
    return tenant;
  }

  public void setTenant(String tenant) {
    this.tenant = tenant;
  }

  public AuthSchemeLookupData userName(String userName) {
    this.userName = userName;
    return this;
  }

   /**
   * Get userName
   * @return userName
  **/
  @ApiModelProperty(required = true, value = "")
  public String getUserName() {
    return userName;
  }

  public void setUserName(String userName) {
    this.userName = userName;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    AuthSchemeLookupData authSchemeLookupData = (AuthSchemeLookupData) o;
    return Objects.equals(this.tenant, authSchemeLookupData.tenant) &&
        Objects.equals(this.userName, authSchemeLookupData.userName);
  }

  @Override
  public int hashCode() {
    return Objects.hash(tenant, userName);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class AuthSchemeLookupData {\n");
    
    sb.append("    tenant: ").append(toIndentedString(tenant)).append("\n");
    sb.append("    userName: ").append(toIndentedString(userName)).append("\n");
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

