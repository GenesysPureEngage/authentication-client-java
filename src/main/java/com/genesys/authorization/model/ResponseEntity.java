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
 * ResponseEntity
 */
@javax.annotation.Generated(value = "io.swagger.codegen.languages.JavaClientCodegen", date = "2017-07-26T17:23:00.879Z")
public class ResponseEntity {
  @SerializedName("body")
  private Object body = null;

  /**
   * Gets or Sets statusCode
   */
  public enum StatusCodeEnum {
    @SerializedName("100")
    _100("100"),
    
    @SerializedName("101")
    _101("101"),
    
    @SerializedName("102")
    _102("102"),
    
    @SerializedName("103")
    _103("103"),
    
    @SerializedName("200")
    _200("200"),
    
    @SerializedName("201")
    _201("201"),
    
    @SerializedName("202")
    _202("202"),
    
    @SerializedName("203")
    _203("203"),
    
    @SerializedName("204")
    _204("204"),
    
    @SerializedName("205")
    _205("205"),
    
    @SerializedName("206")
    _206("206"),
    
    @SerializedName("207")
    _207("207"),
    
    @SerializedName("208")
    _208("208"),
    
    @SerializedName("226")
    _226("226"),
    
    @SerializedName("300")
    _300("300"),
    
    @SerializedName("301")
    _301("301"),
    
    @SerializedName("302")
    _302("302"),
    
    @SerializedName("303")
    _303("303"),
    
    @SerializedName("304")
    _304("304"),
    
    @SerializedName("305")
    _305("305"),
    
    @SerializedName("307")
    _307("307"),
    
    @SerializedName("308")
    _308("308"),
    
    @SerializedName("400")
    _400("400"),
    
    @SerializedName("401")
    _401("401"),
    
    @SerializedName("402")
    _402("402"),
    
    @SerializedName("403")
    _403("403"),
    
    @SerializedName("404")
    _404("404"),
    
    @SerializedName("405")
    _405("405"),
    
    @SerializedName("406")
    _406("406"),
    
    @SerializedName("407")
    _407("407"),
    
    @SerializedName("408")
    _408("408"),
    
    @SerializedName("409")
    _409("409"),
    
    @SerializedName("410")
    _410("410"),
    
    @SerializedName("411")
    _411("411"),
    
    @SerializedName("412")
    _412("412"),
    
    @SerializedName("413")
    _413("413"),
    
    @SerializedName("414")
    _414("414"),
    
    @SerializedName("415")
    _415("415"),
    
    @SerializedName("416")
    _416("416"),
    
    @SerializedName("417")
    _417("417"),
    
    @SerializedName("418")
    _418("418"),
    
    @SerializedName("419")
    _419("419"),
    
    @SerializedName("420")
    _420("420"),
    
    @SerializedName("421")
    _421("421"),
    
    @SerializedName("422")
    _422("422"),
    
    @SerializedName("423")
    _423("423"),
    
    @SerializedName("424")
    _424("424"),
    
    @SerializedName("426")
    _426("426"),
    
    @SerializedName("428")
    _428("428"),
    
    @SerializedName("429")
    _429("429"),
    
    @SerializedName("431")
    _431("431"),
    
    @SerializedName("451")
    _451("451"),
    
    @SerializedName("500")
    _500("500"),
    
    @SerializedName("501")
    _501("501"),
    
    @SerializedName("502")
    _502("502"),
    
    @SerializedName("503")
    _503("503"),
    
    @SerializedName("504")
    _504("504"),
    
    @SerializedName("505")
    _505("505"),
    
    @SerializedName("506")
    _506("506"),
    
    @SerializedName("507")
    _507("507"),
    
    @SerializedName("508")
    _508("508"),
    
    @SerializedName("509")
    _509("509"),
    
    @SerializedName("510")
    _510("510"),
    
    @SerializedName("511")
    _511("511");

    private String value;

    StatusCodeEnum(String value) {
      this.value = value;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }
  }

  @SerializedName("statusCode")
  private StatusCodeEnum statusCode = null;

  @SerializedName("statusCodeValue")
  private Integer statusCodeValue = null;

  public ResponseEntity body(Object body) {
    this.body = body;
    return this;
  }

   /**
   * Get body
   * @return body
  **/
  @ApiModelProperty(example = "null", value = "")
  public Object getBody() {
    return body;
  }

  public void setBody(Object body) {
    this.body = body;
  }

  public ResponseEntity statusCode(StatusCodeEnum statusCode) {
    this.statusCode = statusCode;
    return this;
  }

   /**
   * Get statusCode
   * @return statusCode
  **/
  @ApiModelProperty(example = "null", value = "")
  public StatusCodeEnum getStatusCode() {
    return statusCode;
  }

  public void setStatusCode(StatusCodeEnum statusCode) {
    this.statusCode = statusCode;
  }

  public ResponseEntity statusCodeValue(Integer statusCodeValue) {
    this.statusCodeValue = statusCodeValue;
    return this;
  }

   /**
   * Get statusCodeValue
   * @return statusCodeValue
  **/
  @ApiModelProperty(example = "null", value = "")
  public Integer getStatusCodeValue() {
    return statusCodeValue;
  }

  public void setStatusCodeValue(Integer statusCodeValue) {
    this.statusCodeValue = statusCodeValue;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ResponseEntity responseEntity = (ResponseEntity) o;
    return Objects.equals(this.body, responseEntity.body) &&
        Objects.equals(this.statusCode, responseEntity.statusCode) &&
        Objects.equals(this.statusCodeValue, responseEntity.statusCodeValue);
  }

  @Override
  public int hashCode() {
    return Objects.hash(body, statusCode, statusCodeValue);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ResponseEntity {\n");
    
    sb.append("    body: ").append(toIndentedString(body)).append("\n");
    sb.append("    statusCode: ").append(toIndentedString(statusCode)).append("\n");
    sb.append("    statusCodeValue: ").append(toIndentedString(statusCodeValue)).append("\n");
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

