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
import com.genesys.authorization.model.ApiResponseStatus;
import com.genesys.authorization.model.ClientDetails;
import com.genesys.authorization.model.CollectionApiResponseListClientDetails;
import com.google.gson.annotations.SerializedName;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.util.ArrayList;
import java.util.List;

/**
 * ApiResponseListClientDetails
 */
@javax.annotation.Generated(value = "io.swagger.codegen.languages.JavaClientCodegen", date = "2017-08-08T19:22:59.740Z")
public class ApiResponseListClientDetails {
  @SerializedName("data")
  private List<ClientDetails> data = new ArrayList<ClientDetails>();

  @SerializedName("errors")
  private CollectionApiResponseListClientDetails errors = null;

  @SerializedName("path")
  private String path = null;

  @SerializedName("status")
  private ApiResponseStatus status = null;

  public ApiResponseListClientDetails data(List<ClientDetails> data) {
    this.data = data;
    return this;
  }

  public ApiResponseListClientDetails addDataItem(ClientDetails dataItem) {
    this.data.add(dataItem);
    return this;
  }

   /**
   * Get data
   * @return data
  **/
  @ApiModelProperty(example = "null", value = "")
  public List<ClientDetails> getData() {
    return data;
  }

  public void setData(List<ClientDetails> data) {
    this.data = data;
  }

  public ApiResponseListClientDetails errors(CollectionApiResponseListClientDetails errors) {
    this.errors = errors;
    return this;
  }

   /**
   * Get errors
   * @return errors
  **/
  @ApiModelProperty(example = "null", value = "")
  public CollectionApiResponseListClientDetails getErrors() {
    return errors;
  }

  public void setErrors(CollectionApiResponseListClientDetails errors) {
    this.errors = errors;
  }

  public ApiResponseListClientDetails path(String path) {
    this.path = path;
    return this;
  }

   /**
   * Get path
   * @return path
  **/
  @ApiModelProperty(example = "null", value = "")
  public String getPath() {
    return path;
  }

  public void setPath(String path) {
    this.path = path;
  }

  public ApiResponseListClientDetails status(ApiResponseStatus status) {
    this.status = status;
    return this;
  }

   /**
   * Get status
   * @return status
  **/
  @ApiModelProperty(example = "null", required = true, value = "")
  public ApiResponseStatus getStatus() {
    return status;
  }

  public void setStatus(ApiResponseStatus status) {
    this.status = status;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ApiResponseListClientDetails apiResponseListClientDetails = (ApiResponseListClientDetails) o;
    return Objects.equals(this.data, apiResponseListClientDetails.data) &&
        Objects.equals(this.errors, apiResponseListClientDetails.errors) &&
        Objects.equals(this.path, apiResponseListClientDetails.path) &&
        Objects.equals(this.status, apiResponseListClientDetails.status);
  }

  @Override
  public int hashCode() {
    return Objects.hash(data, errors, path, status);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ApiResponseListClientDetails {\n");
    
    sb.append("    data: ").append(toIndentedString(data)).append("\n");
    sb.append("    errors: ").append(toIndentedString(errors)).append("\n");
    sb.append("    path: ").append(toIndentedString(path)).append("\n");
    sb.append("    status: ").append(toIndentedString(status)).append("\n");
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

