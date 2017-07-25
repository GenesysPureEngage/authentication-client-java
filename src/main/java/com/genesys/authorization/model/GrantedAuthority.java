/*
 * Authorization API
 * Authorization API
 *
 * OpenAPI spec version: 9.0.000.00.598
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.genesys.authorization.model;

import java.util.Objects;
import com.google.gson.annotations.SerializedName;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

/**
 * GrantedAuthority
 */
@javax.annotation.Generated(value = "io.swagger.codegen.languages.JavaClientCodegen", date = "2017-07-25T22:23:03.326Z")
public class GrantedAuthority {
  @SerializedName("authority")
  private String authority = null;

  public GrantedAuthority authority(String authority) {
    this.authority = authority;
    return this;
  }

   /**
   * Get authority
   * @return authority
  **/
  @ApiModelProperty(example = "null", value = "")
  public String getAuthority() {
    return authority;
  }

  public void setAuthority(String authority) {
    this.authority = authority;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    GrantedAuthority grantedAuthority = (GrantedAuthority) o;
    return Objects.equals(this.authority, grantedAuthority.authority);
  }

  @Override
  public int hashCode() {
    return Objects.hash(authority);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class GrantedAuthority {\n");
    
    sb.append("    authority: ").append(toIndentedString(authority)).append("\n");
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

