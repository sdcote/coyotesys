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
import java.util.Date;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

import coyote.commons.network.http.Body;
import coyote.commons.network.http.HTTPD;
import coyote.commons.network.http.IHTTPSession;
import coyote.commons.network.http.Response;
import coyote.commons.network.http.ResponseException;
import coyote.commons.network.http.Status;
import coyote.commons.network.http.responder.Resource;
import coyote.commons.network.http.responder.Responder;
import coyote.dataframe.DataField;
import coyote.dataframe.DataFrame;
import coyote.dataframe.marshal.JSONMarshaler;
import coyote.dataframe.marshal.MarshalException;
import coyote.loader.log.Log;


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
 * 
 * "/api/checkin" : { "Class" : "systems.coyote.responder.CheckIn" },
 * "/api/checkin/:id" : { "Class" : "systems.coyote.responder.CheckIn" },
 */
public class CheckIn extends AbstractJsonResponder implements Responder {

  private static final String STATUS = "status";
  private static final String NAME = "InstanceName";
  private static final String ID = "InstanceId";
  private static final String ADDRESS = "IpAddress";
  private static final String LASTSEEN = "LastCheckIn";

  public static final Map<String, DataFrame> componentsById = new Hashtable<String, DataFrame>();
  public static final Map<String, DataFrame> componentsByName = new Hashtable<String, DataFrame>();
  public static final Map<String, DataFrame> componentsByIP = new Hashtable<String, DataFrame>();




  /**
   * @see coyote.commons.network.http.responder.DefaultResponder#get(coyote.commons.network.http.responder.Resource, java.util.Map, coyote.commons.network.http.IHTTPSession)
   */
  @Override
  public Response get( Resource resource, Map<String, String> urlParams, IHTTPSession session ) {
    // Get the command from the URL parameters specified when we were registered with the router 
    String name = urlParams.get( "id" );
    // /checkin/  - get all
    // /checkin/:name  - get all with this name

    // TODO Auto-generated method stub

    return Response.createFixedLengthResponse( getStatus(), getMimeType(), getText() );
  }




  /**
   * Put the given body in a map of other bodies by its ID
   * 
   * <p>As long as the body is a valid JSON and it contains a top level field 
   * of an id, name or IP address, store it.
   * 
   * @see coyote.commons.network.http.responder.DefaultStreamResponder#put(coyote.commons.network.http.responder.Resource, java.util.Map, coyote.commons.network.http.IHTTPSession)
   */
  @Override
  public Response put( Resource resource, Map<String, String> urlParams, IHTTPSession session ) {

    Body body = null;
    try {
      body = session.parseBody();

      for ( String name : body.keySet() ) {
        String strdata = body.getAsString( name );
        Log.info( this.getClass().getSimpleName() + " marshaling '" + name + "' type " + body.getEntityType( name ) + " body of '" + strdata.substring( 0, strdata.length() > 500 ? 500 : strdata.length() ) + ( strdata.length() <= 500 ? "'" : " ...'" ) );
      }
    } catch ( IOException | ResponseException e ) {
      Log.append( HTTPD.EVENT, "ERROR: Could not parse body: " + e.getClass().getSimpleName() + " - " + e.getMessage() );
    }

    if ( body != null ) {
      try {
        List<DataFrame> frames = JSONMarshaler.marshal( body.getContent() );
        if ( frames.size() > 0 ) {
          DataFrame frame = frames.get( 0 );
          frame.put( LASTSEEN, new Date() );
          DataField field = frame.getFieldIgnoreCase( NAME );
          if ( field != null && field.isNotNull() ) {
            componentsByName.put( field.getStringValue(), frame );
          }
          field = frame.getFieldIgnoreCase( ID );
          if ( field != null && field.isNotNull() ) {
            componentsById.put( field.getStringValue(), frame );
          }
          field = frame.getFieldIgnoreCase( ADDRESS );
          if ( field != null && field.isNotNull() ) {
            componentsByIP.put( field.getStringValue(), frame );
          }
          results.set( STATUS, "success" );
        } else {
          setStatus( Status.BAD_REQUEST );
          results.set( STATUS, "No objects found in request" );
        }
      } catch ( MarshalException e ) {
        setStatus( Status.BAD_REQUEST );
        results.set( STATUS, "Problems parsing body of the request: " + e.getMessage() );
      }
    } else {
      setStatus( Status.BAD_REQUEST );
      results.set( STATUS, "Problems parsing body of the request" );
    }

    Log.info( "Profiles by Name:" + componentsByName.size() + " ID:" + componentsById.size() + " Address:" + componentsByIP.size() );
    return Response.createFixedLengthResponse( getStatus(), getMimeType(), getText() );
  }

}
