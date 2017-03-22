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
package coyote.sdc.handler;

import java.util.Map;

import coyote.commons.StringUtil;
import coyote.commons.network.http.IHTTPSession;
import coyote.commons.network.http.Response;
import coyote.commons.network.http.auth.Auth;
import coyote.commons.network.http.handler.UriResource;
import coyote.commons.network.http.handler.UriResponder;


/**
 * This returns data for the current logged-in user.
 * 
 * <p>A common use case is the retrieval of navigation details clients can use 
 * to display in their respective environments. CLI components may call this 
 * method when the --help option is used to show what other commands can be 
 * executed. Web clients can use the results to build navigation menus for the 
 * currently logged-in user.
 * 
 * <p>This relies on the Auth annotation to populate the session with the user 
 * name. The required=false allows the Auth annotation to perform the check and 
 * populate the user, but not reject the request if the authentication fails. 
 * 
 * <p>If the user is not logged-in, nothing is returned "{}".
 */
@Auth(required = false)
public class UserProfileHandler extends AbstractJsonHandler implements UriResponder {

  /**
   * 
   */
  @Override
  public Response get( UriResource uriResource, Map<String, String> urlParams, IHTTPSession session ) {
    if ( StringUtil.isNotBlank( session.getUserName() ) ) {
      results.add( "username", session.getUserName() );
      // Perform a look-up of the user
      // show stuff the client can use
      // put it all in the results
    }

    return Response.createFixedLengthResponse( getStatus(), getMimeType(), getText() );
  }

}
