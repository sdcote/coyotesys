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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;

import coyote.commons.StringUtil;
import coyote.commons.network.http.HTTPD;
import coyote.commons.network.http.IHTTPSession;
import coyote.commons.network.http.Response;
import coyote.commons.network.http.auth.Auth;
import coyote.commons.network.http.handler.HTTPDRouter;
import coyote.commons.network.http.handler.UriResource;
import coyote.commons.network.http.handler.UriResponder;
import coyote.loader.log.Log;


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

  
  private void logRequestDetails( UriResource uriResource, IHTTPSession session ) {
    Map<String, String> header = session.getRequestHeaders();
    Map<String, String> parms = session.getParms();
    String uri = session.getUri();

    final String baseUri = uriResource.getUri();

    session.getQueryParameterString();

    // Print 
    if ( Log.isLogging( Log.DEBUG_EVENTS ) ) {
      StringBuffer b = new StringBuffer( "DEBUG: " );

      b.append( session.getMethod() + " '" + uri + "' \r\n" );

      Iterator<String> e = header.keySet().iterator();
      while ( e.hasNext() ) {
        String value = e.next();
        b.append( "   HDR: '" + value + "' = '" + header.get( value ) + "'\r\n" );
      }
      e = parms.keySet().iterator();
      while ( e.hasNext() ) {
        String value = e.next();
        b.append( "   PRM: '" + value + "' = '" + parms.get( value ) + "'\r\n" );
      }
      Log.append( HTTPD.EVENT, b.toString() );
    }

    Log.append( HTTPD.EVENT, "ResourceHandler servicing request for " + baseUri );

    String realUri = HTTPDRouter.normalizeUri( session.getUri() );

    for ( int index = 0; index < Math.min( baseUri.length(), realUri.length() ); index++ ) {
      if ( baseUri.charAt( index ) != realUri.charAt( index ) ) {
        realUri = HTTPDRouter.normalizeUri( realUri.substring( index ) );
        break;
      }
    }
    Log.append( HTTPD.EVENT, "ResourceHandler processed request for real URI '" + realUri + "'" );
  }

  
  
  /**
   * Split the pat up into an array of directories and a file , the last element
   */
  private static String[] getPathArray( final String uri ) {
    final String array[] = uri.split( "/" );
    final ArrayList<String> pathArray = new ArrayList<String>();

    for ( final String s : array ) {
      if ( s.length() > 0 ) {
        pathArray.add( s );
      }
    }
    return pathArray.toArray( new String[] {} );
  }

}
