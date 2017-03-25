/*
 * Copyright (c) 2017 Stephan D. Cote' - All rights reserved.
 * 
 * This program and the accompanying materials are made available under the 
 * terms of the MIT License which accompanies this distribution, and is 
 * available at http://creativecommons.org/licenses/MIT/
 *
 * Contributors:
 *   Stephan D. Cote 
 *      - Initial concept and initial implementation
 */
package systems.coyote.handler;

import java.net.InetAddress;
import java.util.Iterator;
import java.util.Map;

import coyote.commons.DateUtil;
import coyote.commons.StringUtil;
import coyote.commons.network.http.IHTTPSession;
import coyote.commons.network.http.Response;
import coyote.commons.network.http.auth.Auth;
import coyote.commons.network.http.handler.UriResource;
import coyote.commons.network.http.handler.UriResponder;
import coyote.dataframe.DataFrame;
import coyote.i13n.ArmMaster;
import coyote.i13n.Counter;
import coyote.i13n.Gauge;
import coyote.i13n.StatBoard;
import coyote.i13n.State;
import coyote.i13n.TimingMaster;
import coyote.loader.cfg.Config;
import coyote.loader.log.Log;
import systems.coyote.WebServer;


/**
 * This provides access to all the stats in the for the loader(server).
 * 
 * <p>This is expected to the added to the WebServer thusly:<pre>
 * "/api/stat/" : { "Class" : "systems.coyote.handler.StatBoardHandler" },
 * "/api/stat/:metric" : { "Class" : "systems.coyote.handler.StatBoardHandler" },
 * "/api/stat/:metric/:name" : { "Class" : "systems.coyote.handler.StatBoardHandler" },
 * </pre>    
 * If no metric or name is given, then the entire statistics board is 
 * serialized as a response. If a metric is given, but no name then all the 
 * metrics of that type are returned. Otherwise just the named metric is returned.
 * 
 * <p>Authentication is performed, but not required so logged-in user can be 
 * identified for logging purposes.
 */
@Auth(required = false)
public class StatBoardHandler extends AbstractJsonHandler implements UriResponder {
  private static final String ARM = "ARM";
  private static final String TIMER = "Timer";
  private static final String GAUGE = "Gauge";
  private static final String STATUS = "Status";
  private static final String COUNTER = "Counter";
  private static final String VERSION = "Version";
  private static final String HOSTNAME = "DnsName";
  private static final String OS_ARCH = "OSArch";
  private static final String OS_NAME = "OSName";
  private static final String OS_VERSION = "OSVersion";
  private static final String RUNTIME_NAME = "RuntimeName";
  private static final String RUNTIME_VENDOR = "RuntimeVendor";
  private static final String RUNTIME_VERSION = "RuntimeVersion";
  private static final String STARTED = "Started";
  private static final String STATE = "State";
  private static final String USER_NAME = "Account";
  private static final String VM_AVAIL_MEM = "AvailableMemory";
  private static final String VM_CURR_HEAP = "CurrentHeap";
  private static final String VM_FREE_HEAP = "FreeHeap";
  private static final String VM_FREE_MEM = "FreeMemory";
  private static final String VM_HEAP_PCT = "HeapPercentage";
  private static final String VM_MAX_HEAP = "MaxHeapSize";
  private static final String FIXTURE_ID = "InstanceId";
  private static final String HOSTADDR = "IpAddress";
  private static final String NAME = "Name";
  private static final String UPTIME = "Uptime";




  /**
   * 
   */
  @Override
  public Response get( UriResource uriResource, Map<String, String> urlParams, IHTTPSession session ) {
    WebServer loader = uriResource.initParameter( 0, WebServer.class );
    Config config = uriResource.initParameter( 1, Config.class );

    // get a reference to the stats board of our loader, which should be the web server as well
    StatBoard statboard = loader.getStats();

    // Get the command from the URL parameters specified when we were registered with the router 
    String metric = urlParams.get( "metric" );
    String name = urlParams.get( "name" );

    // we are going to format the output 
    setFormattingJson( true );

    if ( statboard != null ) {
      if ( StringUtil.isNotBlank( metric ) ) {
        if ( StringUtil.isNotBlank( metric ) ) {

        } else {

        }
      } else {
        results.merge( createStatus( statboard ) );
      }
    }

    // create a response using the superclass methods
    return Response.createFixedLengthResponse( super.getStatus(), super.getMimeType(), super.getText() );
  }




  private DataFrame createStatus( StatBoard statboard ) {
    DataFrame retval = new DataFrame();
    retval.add( NAME, STATUS );

    // Add information from the statboard  fixture
    retval.add( FIXTURE_ID, statboard.getId() );
    retval.add( OS_NAME, System.getProperty( "os.name" ) );
    retval.add( OS_ARCH, System.getProperty( "os.arch" ) );
    retval.add( OS_VERSION, System.getProperty( "os.version" ) );
    retval.add( RUNTIME_VERSION, System.getProperty( "java.version" ) );
    retval.add( RUNTIME_VENDOR, System.getProperty( "java.vendor" ) );
    retval.add( RUNTIME_NAME, "Java" );
    retval.add( STARTED, DateUtil.ISO8601Format( statboard.getStartedTime() ) );
    retval.add( UPTIME, DateUtil.formatSignificantElapsedTime( ( System.currentTimeMillis() - statboard.getStartedTime() ) / 1000 ) );
    retval.add( USER_NAME, System.getProperty( "user.name" ) );
    retval.add( VM_AVAIL_MEM, new Long( statboard.getAvailableMemory() ) );
    retval.add( VM_CURR_HEAP, new Long( statboard.getCurrentHeapSize() ) );
    retval.add( VM_FREE_HEAP, new Long( statboard.getFreeHeapSize() ) );
    retval.add( VM_FREE_MEM, new Long( statboard.getFreeMemory() ) );
    retval.add( VM_MAX_HEAP, new Long( statboard.getMaxHeapSize() ) );
    retval.add( VM_HEAP_PCT, new Float( statboard.getHeapPercentage() ) );
    String text = statboard.getHostname();
    retval.add( HOSTNAME, ( text == null ) ? "unknown" : text );
    InetAddress addr = statboard.getHostIpAddress();
    retval.add( HOSTADDR, ( addr == null ) ? "unknown" : addr.getHostAddress() );

    DataFrame childPacket = new DataFrame();

    // get the list of component versions registered with the statboard
    Map<String, String> versions = statboard.getVersions();
    for ( String key : versions.keySet() ) {
      childPacket.add( key, versions.get( key ) );
    }
    retval.add( VERSION, childPacket );

    // Get all counters
    childPacket.clear();
    for ( Iterator it = statboard.getCounterIterator(); it.hasNext(); ) {
      Counter counter = (Counter)it.next();
      childPacket.add( counter.getName(), new Long( counter.getValue() ) );
    }
    retval.add( COUNTER, childPacket );

    // Get all states
    childPacket.clear();
    for ( Iterator it = statboard.getStateIterator(); it.hasNext(); ) {
      State state = (State)it.next();
      if ( state.getValue() != null ) {
        childPacket.add( state.getName(), state.getValue() );
      } else {
        Log.info( "State " + state.getName() + " is null" );
      }
    }
    retval.add( STATE, childPacket );

    childPacket.clear();
    for ( Iterator it = statboard.getGaugeIterator(); it.hasNext(); ) {
      DataFrame packet = ( (Gauge)it.next() ).toFrame();
      if ( packet != null ) {
        childPacket.add( packet );
      }
    }
    retval.add( GAUGE, childPacket );

    childPacket.clear();
    for ( Iterator it = statboard.getTimerIterator(); it.hasNext(); ) {
      DataFrame cap = ( (TimingMaster)it.next() ).toFrame();
      if ( cap != null ) {
        childPacket.add( cap );
      }
    }
    retval.add( TIMER, childPacket );

    childPacket.clear();
    for ( Iterator it = statboard.getArmIterator(); it.hasNext(); ) {
      DataFrame cap = ( (ArmMaster)it.next() ).toFrame();
      if ( cap != null ) {
        childPacket.add( cap );
      }
    }
    retval.add( ARM, childPacket );

    return retval;
  }

}
