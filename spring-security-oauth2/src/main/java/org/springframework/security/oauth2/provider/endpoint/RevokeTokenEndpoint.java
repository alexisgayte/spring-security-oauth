/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.provider.endpoint;

import java.security.Principal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * 
 */
@FrameworkEndpoint
public class RevokeTokenEndpoint {

	private ConsumerTokenServices consumerTokenServices;
	
	private ResourceServerTokenServices resourceServerTokenServices;
	
	protected final Log logger = LogFactory.getLog(getClass());

	private WebResponseExceptionTranslator exceptionTranslator = new DefaultWebResponseExceptionTranslator();

	public RevokeTokenEndpoint(ConsumerTokenServices consumerTokenServices, ResourceServerTokenServices resourceServerTokenServices) {
		this.consumerTokenServices = consumerTokenServices;
		this.resourceServerTokenServices = resourceServerTokenServices;
	}
	
	/**
	 * @param exceptionTranslator the exception translator to set
	 */
	public void setExceptionTranslator(WebResponseExceptionTranslator exceptionTranslator) {
		this.exceptionTranslator = exceptionTranslator;
	}

	@RequestMapping(value = "/oauth/revoke", method = RequestMethod.POST)
	@ResponseStatus(value = HttpStatus.OK)
	public void revokeToken(@RequestParam("token") final String value, 
							@RequestParam(value = "token_hint", required = false) final String tokenHint,
							Principal principal) {

		if (!(principal instanceof OAuth2Authentication) 
					|| !((OAuth2Authentication) principal).isAuthenticated() 
					|| !((OAuth2Authentication) principal).isClientOnly()) {
			throw new InsufficientAuthenticationException(
					"User must be authenticated with Spring Security before authorization can be completed.");
		}
		
		OAuth2AccessToken token = resourceServerTokenServices.readAccessToken(value);
		if (token == null) {
			throw new InvalidTokenException("Token was not recognised");
		}

		if (token.isExpired()) {
			throw new InvalidTokenException("Token has expired");
		}

		consumerTokenServices.revokeToken(token.getValue());
	}

    @ExceptionHandler(OAuth2Exception.class)
    public ResponseEntity<OAuth2Exception> handleException(Exception e) throws Exception {

        return exceptionTranslator.translate(e);
    }
}
