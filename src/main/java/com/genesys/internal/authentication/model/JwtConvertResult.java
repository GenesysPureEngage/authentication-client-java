/*
 * Authentication API
 * Authentication API
 *
 * OpenAPI spec version: 9.0.000.10.1112
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.genesys.internal.authentication.model;

import java.util.Objects;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.io.IOException;

/**
 * JwtConvertResult
 */
@javax.annotation.Generated(value = "io.swagger.codegen.languages.JavaClientCodegen", date = "2018-05-03T20:03:28.768Z")
public class JwtConvertResult {
  @SerializedName("jwtToken")
  private String jwtToken = null;

  public JwtConvertResult jwtToken(String jwtToken) {
    this.jwtToken = jwtToken;
    return this;
  }

   /**
   * Get jwtToken
   * @return jwtToken
  **/
  @ApiModelProperty(value = "")
  public String getJwtToken() {
    return jwtToken;
  }

  public void setJwtToken(String jwtToken) {
    this.jwtToken = jwtToken;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    JwtConvertResult jwtConvertResult = (JwtConvertResult) o;
    return Objects.equals(this.jwtToken, jwtConvertResult.jwtToken);
  }

  @Override
  public int hashCode() {
    return Objects.hash(jwtToken);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class JwtConvertResult {\n");
    
    sb.append("    jwtToken: ").append(toIndentedString(jwtToken)).append("\n");
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

