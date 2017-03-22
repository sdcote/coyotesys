/*
 * Copyright (c) 2017 Stephan D. Cote' - All rights reserved.
 * 
 * This program and the accompanying materials are made available under the 
 * terms of the MIT License which accompanies this distribution, and is 
 * available at http://creativecommons.org/licenses/MIT/
 *
 * Contributors:
 *   Stephan D. Cote 
 *      - Initial concept and implementation
 */
package systems.coyote.handler;

import java.util.Map;

import coyote.commons.network.http.IHTTPSession;
import coyote.commons.network.http.Response;
import coyote.commons.network.http.auth.Auth;
import coyote.commons.network.http.handler.UriResource;
import coyote.commons.network.http.handler.UriResponder;


/**
 * This handles the contact me form.
 */
@Auth(required = false)
public class ContactHandler extends AbstractJsonHandler implements UriResponder {

  /**
   * 
   */
  @Override
  public Response post( UriResource uriResource, Map<String, String> urlParams, IHTTPSession session ) {
    // TODO: implement a mailer...maybe a log entry?
    return Response.createFixedLengthResponse( getStatus(), getMimeType(), getText() );
  }

}
