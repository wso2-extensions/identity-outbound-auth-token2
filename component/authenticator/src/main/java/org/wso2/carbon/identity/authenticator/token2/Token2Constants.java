/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.token2;

public class Token2Constants {
    public static final String AUTHENTICATOR_NAME = "Token2";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Token2Authenticator";
    public static final String CODE = "code";
    public static final String APIKEY = "apiKey";
    public static final String API = "api";
    public static final String JSON_FORMAT = "1";
    public static final String TOKEN = "token";
    public static final String USER_ID = "userid";
    public static final String VALIDATION = "validation";
    public static final String FORMAT = "format";
    public static final String GET_METHOD = "GET";
    public static final String USERID_CLAIM = "http://wso2.org/claims/identity/userid";
    public static final String EQUAL = "=";
    public static final String AMPERSAND = "&";
    public static final String LOGIN_PAGE = "token2authenticationendpoint/token2.jsp";
    public static final String RETRY_PARAMS = "&authFailure=true&authFailureMsg=login.fail.message";
    public static final String TOKEN2_VALIDATE_ENDPOINT = "https://api.token2.com/validate?";

}