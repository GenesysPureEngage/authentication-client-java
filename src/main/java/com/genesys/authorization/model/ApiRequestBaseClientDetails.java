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
import com.genesys.authorization.model.BaseClientDetails;
import com.google.gson.annotations.SerializedName;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

/**
 * ApiRequestBaseClientDetails
 */
@javax.annotation.Generated(value = "io.swagger.codegen.languages.JavaClientCodegen", date = "2017-07-21T20:52:51.358Z")
public class ApiRequestBaseClientDetails {
  @SerializedName("data")
  private BaseClientDetails data = null;

  @SerializedName("operationId")
  private String operationId = null;

  public ApiRequestBaseClientDetails data(BaseClientDetails data) {
    this.data = data;
    return this;
  }

   /**
   * Get data
   * @return data
  **/
  @ApiModelProperty(example = "null", value = "")
  public BaseClientDetails getData() {
    return data;
  }

  public void setData(BaseClientDetails data) {
    this.data = data;
  }

  public ApiRequestBaseClientDetails operationId(String operationId) {
    this.operationId = operationId;
    return this;
  }

   /**
   * Used for asynchronous operations to map request and response
   * @return operationId
  **/
  @ApiModelProperty(example = "null", value = "Used for asynchronous operations to map request and response")
  public String getOperationId() {
    return operationId;
  }

  public void setOperationId(String operationId) {
    this.operationId = operationId;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ApiRequestBaseClientDetails apiRequestBaseClientDetails = (ApiRequestBaseClientDetails) o;
    return Objects.equals(this.data, apiRequestBaseClientDetails.data) &&
        Objects.equals(this.operationId, apiRequestBaseClientDetails.operationId);
  }

  @Override
  public int hashCode() {
    return Objects.hash(data, operationId);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ApiRequestBaseClientDetails {\n");
    
    sb.append("    data: ").append(toIndentedString(data)).append("\n");
    sb.append("    operationId: ").append(toIndentedString(operationId)).append("\n");
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

