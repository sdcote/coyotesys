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
package systems.coyote.responder;

import java.io.IOException;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

import coyote.commons.network.http.HTTPD;
import coyote.commons.network.http.IHTTPSession;
import coyote.commons.network.http.Response;
import coyote.commons.network.http.ResponseException;
import coyote.commons.network.http.responder.Resource;
import coyote.commons.network.http.responder.Responder;
import coyote.dataframe.DataFrame;
import coyote.loader.cfg.Config;
import coyote.loader.log.Log;
import systems.coyote.WebServer;


/**
 * This is a special responder which accepts POSTs from components and GETs 
 * from clients to allow components running in DHCP environments to register 
 * themselves with other components.
 * 
 * <p>Components with a CheckIn job, simply posts its stats (from their 
 * statistics board) to the URI in its configuration. The CheckIn service then 
 * keeps a list of these stats in memory for managers to retrieve. This way, 
 * components whose IP address changes can report their current IP for 
 * managers to use in locating them. It also gives basic monitoring data to 
 * managers with having them contact the component directly.
 */
public class CheckInResponder extends AbstractJsonResponder implements Responder {

  public static final Map<String, DataFrame> components = new Hashtable<String, DataFrame>();




  /**
   * @see coyote.commons.network.http.responder.DefaultResponder#get(coyote.commons.network.http.responder.Resource, java.util.Map, coyote.commons.network.http.IHTTPSession)
   */
  @Override
  public Response get( Resource resource, Map<String, String> urlParams, IHTTPSession session ) {
    final WebServer loader = resource.initParameter( 0, WebServer.class );
    final Config config = resource.initParameter( 1, Config.class );

    // Get the command from the URL parameters specified when we were registered with the router 
    String name = urlParams.get( "name" );
    // /checkin/  - get all
    // /checkin/:name  - get all with this name

    // TODO Auto-generated method stub

    return Response.createFixedLengthResponse( getStatus(), getMimeType(), getText() );
  }




  /**
   * Put the given body in a map of other bodies by its ID
   * 
   * <p>As long as the body is a valid JSON and it contains a top level field 
   * of "id" (case in-sensitive), store it.
   * 
   * @see coyote.commons.network.http.responder.DefaultStreamResponder#put(coyote.commons.network.http.responder.Resource, java.util.Map, coyote.commons.network.http.IHTTPSession)
   */
  @Override
  public Response put( Resource resource, Map<String, String> urlParams, IHTTPSession session ) {
    final WebServer loader = resource.initParameter( 0, WebServer.class );
    final Config config = resource.initParameter( 1, Config.class );

    Map<String, String> files = new HashMap<String, String>();
    try {
      session.parseBody( files );

      for ( String name : files.keySet() ) {
        String body = files.get( name );
        Log.info( this.getClass().getSimpleName() + " marshaling '" + name + "' body of '" + body.substring( 0, body.length() > 500 ? 500 : body.length() ) + ( body.length() <= 500 ? "'" : " ...'" ) );
      }
    } catch ( IOException | ResponseException e ) {
      Log.append( HTTPD.EVENT, "ERROR: Could not parse body: " + e.getClass().getSimpleName() + " - " + e.getMessage() );
    }
    
    // If there is a valid data frame in the body
    
    // If the frame contains an ID
    
    // Store the frame in the map by its ID

    // TODO Auto-generated method stub
    results.set( "status", "success" );
    return Response.createFixedLengthResponse( getStatus(), getMimeType(), getText() );
  }

}
