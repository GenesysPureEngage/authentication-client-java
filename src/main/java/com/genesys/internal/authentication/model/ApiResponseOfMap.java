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
import com.genesys.internal.authentication.model.ErrorResponse;
import com.genesys.internal.authentication.model.ResponseStatus;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * ApiResponseOfMap
 */
@javax.annotation.Generated(value = "io.swagger.codegen.languages.JavaClientCodegen", date = "2020-08-31T08:40:02.074Z")
public class ApiResponseOfMap {
  @SerializedName("data")
  private Object data = null;

  @SerializedName("errors")
  private List<ErrorResponse> errors = null;

  @SerializedName("path")
  private String path = null;

  @SerializedName("status")
  private ResponseStatus status = null;

  public ApiResponseOfMap data(Object data) {
    this.data = data;
    return this;
  }

   /**
   * Get data
   * @return data
  **/
  @ApiModelProperty(value = "")
  public Object getData() {
    return data;
  }

  public void setData(Object data) {
    this.data = data;
  }

  public ApiResponseOfMap errors(List<ErrorResponse> errors) {
    this.errors = errors;
    return this;
  }

  public ApiResponseOfMap addErrorsItem(ErrorResponse errorsItem) {
    if (this.errors == null) {
      this.errors = new ArrayList<ErrorResponse>();
    }
    this.errors.add(errorsItem);
    return this;
  }

   /**
   * Get errors
   * @return errors
  **/
  @ApiModelProperty(value = "")
  public List<ErrorResponse> getErrors() {
    return errors;
  }

  public void setErrors(List<ErrorResponse> errors) {
    this.errors = errors;
  }

  public ApiResponseOfMap path(String path) {
    this.path = path;
    return this;
  }

   /**
   * Get path
   * @return path
  **/
  @ApiModelProperty(value = "")
  public String getPath() {
    return path;
  }

  public void setPath(String path) {
    this.path = path;
  }

  public ApiResponseOfMap status(ResponseStatus status) {
    this.status = status;
    return this;
  }

   /**
   * Get status
   * @return status
  **/
  @ApiModelProperty(required = true, value = "")
  public ResponseStatus getStatus() {
    return status;
  }

  public void setStatus(ResponseStatus status) {
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
    ApiResponseOfMap apiResponseOfMap = (ApiResponseOfMap) o;
    return Objects.equals(this.data, apiResponseOfMap.data) &&
        Objects.equals(this.errors, apiResponseOfMap.errors) &&
        Objects.equals(this.path, apiResponseOfMap.path) &&
        Objects.equals(this.status, apiResponseOfMap.status);
  }

  @Override
  public int hashCode() {
    return Objects.hash(data, errors, path, status);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ApiResponseOfMap {\n");
    
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

