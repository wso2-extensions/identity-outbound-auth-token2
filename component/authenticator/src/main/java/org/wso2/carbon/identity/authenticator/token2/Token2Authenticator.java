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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Authenticator of Token2
 */
public class Token2Authenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(Token2Authenticator.class);

    /**
     * Get the friendly name of the Authenticator
     */
    public String getFriendlyName() {
        return Token2Constants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    public String getName() {
        return Token2Constants.AUTHENTICATOR_NAME;
    }

    /**
     * Get the Context identifier sent with the request.
     */
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {
        return null;
    }

    /**
     * Check whether the authentication or logout request can be handled by the
     * authenticator
     */
    public boolean canHandle(HttpServletRequest request) {
        if (log.isDebugEnabled()) {
            log.debug("Inside Token2Authenticator canHandle method");
        }
        return StringUtils.isNotEmpty(request.getParameter(Token2Constants.CODE));
    }

    /**
     * Initiate the authentication request
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                .replace("authenticationendpoint/login.do", Token2Constants.LOGIN_PAGE);
        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier());
        String retryParam = "";
        if (context.isRetrying()) {
            retryParam = Token2Constants.RETRY_PARAMS;
        }
        try {
            response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams)) + "&authenticators="
                    + getName() + retryParam);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Authentication failed!", e);
        }
    }

    /**
     * Process the response with the Token2 validation endpoint
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String apiKey = authenticatorProperties.get(Token2Constants.APIKEY);
        String userToken = request.getParameter(Token2Constants.CODE);
        String id = getUserId(context);
        String json = validateToken(Token2Constants.TOKEN2_VALIDATE_ENDPOINT, apiKey, id, Token2Constants.JSON_FORMAT,
                userToken);
        Map<String, Object> userClaims;
        userClaims = JSONUtils.parseJSON(json);
        if (userClaims != null) {
            String validation = String.valueOf(userClaims.get(Token2Constants.VALIDATION));
            if (validation.equals("true")) {
                context.setSubject(AuthenticatedUser
                        .createLocalAuthenticatedUserFromSubjectIdentifier("an authorised user"));
            } else {
                throw new AuthenticationFailedException("Given hardware token has been expired or is not a valid token");
            }
        } else {
            throw new AuthenticationFailedException("UserClaim object is null");
        }
    }

    /**
     * Get the Token2 user id
     *
     * @param context The authentication context
     * @return Token2 userId value
     */
    private String getUserId(AuthenticationContext context) throws AuthenticationFailedException {
        String userId = null;
        String username = getUsername(context);
        if (username != null) {
            UserRealm userRealm = getUserRealm(username);
            username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));
            if (userRealm != null) {
                try {
                    userId = userRealm.getUserStoreManager()
                            .getUserClaimValue(username, Token2Constants.USERID_CLAIM, null);
                } catch (UserStoreException e) {
                    throw new AuthenticationFailedException("Cannot find the user claim for userId " + e.getMessage(),
                            e);
                }
            }
        }
        if (StringUtils.isEmpty(userId)) {
            throw new AuthenticationFailedException("Token2 UserId is null");
        }
        return userId;
    }

    /**
     * Check the validation of the Token2 hardware token whether the token is valid or not
     *
     * @param url    Token2 validation endpoint
     * @param apiKey Token2 ApiKey
     * @param userId Token2 userId
     * @param format Token2 response format
     * @param token  Token2 hardware token
     * @return the response
     */
    private String validateToken(String url, String apiKey, String userId, String format, String token)
            throws AuthenticationFailedException {
        BufferedReader in = null;
        HttpURLConnection urlConnection = null;
        StringBuilder builder;
        if (log.isDebugEnabled()) {
            log.debug("Token validation URL: " + url);
        }
        if (StringUtils.isEmpty(url)) {
            return "";
        } else {
            try {
                URL obj = new URL(url + Token2Constants.API + Token2Constants.EQUAL + apiKey + Token2Constants.AMPERSAND +
                        Token2Constants.TOKEN + Token2Constants.EQUAL + token + Token2Constants.AMPERSAND +
                        Token2Constants.USER_ID + Token2Constants.EQUAL + userId + Token2Constants.AMPERSAND +
                        Token2Constants.FORMAT + Token2Constants.EQUAL + format);
                urlConnection = (HttpURLConnection) obj.openConnection();
                urlConnection.setRequestMethod(Token2Constants.GET_METHOD);
                in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
                builder = new StringBuilder();
                String inputLine = in.readLine();
                while (inputLine != null) {
                    builder.append(inputLine).append("\n");
                    inputLine = in.readLine();
                }
                if (log.isDebugEnabled()) {
                    log.debug("response: " + builder.toString());
                }
            } catch (MalformedURLException e) {
                throw new AuthenticationFailedException("Invalid URL", e);
            } catch (ProtocolException e) {
                throw new AuthenticationFailedException("Error while setting the HTTP request method", e);
            } catch (IOException e) {
                throw new AuthenticationFailedException("Error in I/O Streams" + e.getMessage(), e);
            } finally {
                try {
                    if (in != null) {
                        in.close();
                    }
                } catch (IOException e) {
                    log.error("Couldn't close the I/O Streams", e);
                }
                if (urlConnection != null) {
                    urlConnection.disconnect();
                }
            }
            return builder.toString();
        }
    }

    /**
     * Get the user realm of the logged in user
     */
    private UserRealm getUserRealm(String username) throws AuthenticationFailedException {
        UserRealm userRealm;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = (UserRealm) realmService.getTenantUserRealm(tenantId);
        } catch (Exception e) {
            throw new AuthenticationFailedException("Cannot find the user realm", e);
        }
        return userRealm;
    }

    /**
     * Get the username of the logged in User
     */
    private String getUsername(AuthenticationContext context) {
        String username = null;
        for (Integer stepMap : context.getSequenceConfig().getStepMap().keySet())
            if (context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser() != null
                    && context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedAutenticator()
                    .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                username = String.valueOf(context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser());
                break;
            }
        return username;
    }

    /**
     * Get the configuration properties of UI
     */
    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<>();

        Property apiKey = new Property();
        apiKey.setName(Token2Constants.APIKEY);
        apiKey.setDisplayName("Api Key");
        apiKey.setRequired(true);
        apiKey.setDescription("Enter Token2 API Key value");
        apiKey.setDisplayOrder(1);
        configProperties.add(apiKey);

        Property callbackUrl = new Property();
        callbackUrl.setDisplayName("Callback URL");
        callbackUrl.setName(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
        callbackUrl.setDescription("Enter value corresponding to callback url.");
        callbackUrl.setDisplayOrder(2);
        configProperties.add(callbackUrl);
        return configProperties;
    }
}

