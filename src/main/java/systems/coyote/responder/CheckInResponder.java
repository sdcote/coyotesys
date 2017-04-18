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

import java.util.Map;

import coyote.commons.network.http.IHTTPSession;
import coyote.commons.network.http.Response;
import coyote.commons.network.http.responder.Resource;
import coyote.commons.network.http.responder.Responder;


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

  /**
   * @see coyote.commons.network.http.responder.DefaultResponder#get(coyote.commons.network.http.responder.Resource, java.util.Map, coyote.commons.network.http.IHTTPSession)
   */
  @Override
  public Response get( Resource resource, Map<String, String> urlParams, IHTTPSession session ) {
    // TODO Auto-generated method stub
    return super.get( resource, urlParams, session );
  }

  /**
   * @see coyote.commons.network.http.responder.DefaultStreamResponder#put(coyote.commons.network.http.responder.Resource, java.util.Map, coyote.commons.network.http.IHTTPSession)
   */
  @Override
  public Response put( Resource resource, Map<String, String> urlParams, IHTTPSession session ) {
    // TODO Auto-generated method stub
    return super.put( resource, urlParams, session );
  }

}
