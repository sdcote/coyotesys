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
package systems.coyote;

import java.io.IOException;

import coyote.commons.Version;
import coyote.commons.network.http.HTTPD;
import coyote.commons.network.http.auth.GenericAuthProvider;
import coyote.commons.network.http.handler.HTTPDRouter;
import coyote.commons.network.http.handler.ResourceHandler;
import coyote.dataframe.DataField;
import coyote.dataframe.DataFrameException;
import coyote.loader.AbstractLoader;
import coyote.loader.ConfigTag;
import coyote.loader.Loader;
import coyote.loader.cfg.Config;
import coyote.loader.cfg.ConfigurationException;
import coyote.loader.component.AbstractManagedComponent;
import coyote.loader.component.ManagedComponent;
import coyote.loader.log.Log;
import coyote.loader.log.LogMsg;
import systems.coyote.handler.StatBoardHandler;


/**
 * This starts a configurable web server.
 * 
 * <p>This is a specialization of a Loader which loads a HTTP server and keeps
 * it running in memory.
 */
public class WebServer extends AbstractLoader {
  /** Tag used in various class identifying locations. */
  public static final String CLASS = WebServer.class.getSimpleName();

  private static final int DEFAULT_PORT = 80;

  private static final String PORT = "Port";

  private HTTPDRouter server = null;

  public static final Version VERSION = new Version( 0, 0, 1, Version.EXPERIMENTAL );




  /**
   * @see coyote.loader.AbstractLoader#configure(coyote.loader.cfg.Config)
   */
  @Override
  public void configure( Config cfg ) throws ConfigurationException {
    super.configure( cfg );

    int port = DEFAULT_PORT;

    // we need to get the port first as part of the server constructor
    if ( cfg != null ) {
      for ( DataField field : cfg.getFields() ) {
        if ( PORT.equalsIgnoreCase( field.getName() ) ) {
          try {
            port = Integer.parseInt( field.getStringValue() );
          } catch ( NumberFormatException e ) {
            port = DEFAULT_PORT;
            Log.error( "Port configuration option was not a valid integer, using default" );
          }
        }
      }
    }

    boolean secureServer;
    try {
      secureServer = cfg.getAsBoolean( "SecureServer" );
    } catch ( DataFrameException e1 ) {
      secureServer = false;
    }

    // create a server with the default mappings
    server = new HTTPDRouter( port );

    if ( port == 443 || secureServer ) {
      try {
        server.makeSecure( HTTPD.makeSSLSocketFactory( "/keystore.jks", "password".toCharArray() ), null );
      } catch ( IOException e ) {
        Log.error( "Could not make the server secure: " + e.getMessage() );
      }
    }

    // Add the default routs to ensure basic operation
    server.addDefaultRoutes();

    // remove the root handlers, we'll use ours below
    server.removeRoute( "/" );
    server.removeRoute( "/index.html" );

    // add a statistics board handler
    server.addRoute( "/api/stat/", StatBoardHandler.class, getStats() ); // get the entire statboard
    server.addRoute( "/api/stat/:metric", StatBoardHandler.class, getStats() ); // get all the metrics of a type (e.g. timer)
    server.addRoute( "/api/stat/:metric/:name", StatBoardHandler.class, getStats() ); // get a particular metric

    // Resource handler - higher priority value allows it to be a catch-all
    server.addRoute( "/", Integer.MAX_VALUE, ResourceHandler.class, "content" );
    server.addRoute( "/(.)+", Integer.MAX_VALUE, ResourceHandler.class, "content" );

    if ( cfg != null ) {
      Config section = cfg.getSection( GenericAuthProvider.AUTH_SECTION );
      if ( section != null ) {
        server.setAuthProvider( new GenericAuthProvider( section ) );
      }

      // configure the IPACL with any found configuration data; 
      // localhost only access if no configuration data is found
      server.configIpACL( cfg.getSection( ConfigTag.IPACL ) );

      // Configure Denial of Service frequency tables
      server.configDosTables( cfg.getSection( ConfigTag.FREQUENCY ) );

      // if we have no components defined, install a wedge to keep the server open
      if ( components.size() == 0 ) {
        Wedge wedge = new Wedge();
        wedge.setLoader( this );
        components.put( wedge, cfg );
        activate( wedge, cfg ); // activate it
      }

      // Now configure the server

      // configure the server to use our statistics board
      server.setStatBoard( getStats() );

      // TODO: Make these configurable
      getStats().enableArm( true );
      getStats().enableGauges( true );
      getStats().enableTiming( true );
      getStats().setVersion( CLASS, VERSION );

      // go through each of the mappings and set the given handler in place
      // with its configuration

    }

  }




  /**
   * Start the components running.
   * 
   * @see coyote.loader.AbstractLoader#start()
   */
  @Override
  public void start() {
    // only start once, this is not foolproof as the active flag is set only
    // when the watchdog loop is entered
    if ( isActive() ) {
      return;
    }

    try {
      server.start( HTTPD.SOCKET_READ_TIMEOUT, false );
    } catch ( IOException ioe ) {
      Log.append( HTTPD.EVENT, "ERROR: Could not start server on port '" + server.getPort() + "' - " + ioe.getMessage() );
      System.err.println( "Couldn't start server:\n" + ioe );
      System.exit( 1 );
    }

    // Save the name of the thread that is running this class
    final String oldName = Thread.currentThread().getName();

    // Rename this thread to the name of this class
    Thread.currentThread().setName( CLASS );

    // very important to get park(millis) to operate
    current_thread = Thread.currentThread();

    // Parse through the configuration and initialize all the components
    initComponents();

    Log.info( LogMsg.createMsg( MSG, "Loader.components_initialized" ) );

    // By this time all loggers (including the catch-all logger) should be
    // open
    final StringBuffer b = new StringBuffer( CLASS );
    b.append( " v" );
    b.append( VERSION.toString() );
    b.append( " initialized - Loader:" );
    b.append( Loader.API_NAME );
    b.append( " v" );
    b.append( Loader.API_VERSION );
    b.append( " - Runtime: " );
    b.append( System.getProperty( "java.version" ) );
    b.append( " (" );
    b.append( System.getProperty( "java.vendor" ) );
    b.append( ")" );
    b.append( " - Platform: " );
    b.append( System.getProperty( "os.arch" ) );
    b.append( " OS: " );
    b.append( System.getProperty( "os.name" ) );
    b.append( " (" );
    b.append( System.getProperty( "os.version" ) );
    b.append( ")" );
    Log.info( b );

    // enter a loop performing watchdog and maintenance functions
    watchdog();

    // The watchdog loop has exited, so we are done processing
    terminateComponents();

    Log.info( LogMsg.createMsg( MSG, "Loader.terminated" ) );

    // Rename the thread back to what it was called before we were being run
    Thread.currentThread().setName( oldName );

  }




  /**
   * Shut everything down when the JRE terminates.
   * 
   * <p>There is a shutdown hook registered with the JRE when this Service is
   * loaded. The shutdown hook will call this method when the JRE is 
   * terminating so that the Service can terminate any long-running processes.
   * 
   * <p>Note: this is different from {@code close()} but {@code shutdown()} 
   * will normally result in {@code close()} being invoked at some point.
   * 
   * @see coyote.loader.thread.ThreadJob#shutdown()
   */
  @Override
  public void shutdown() {
    // call the threadjob shutdown to exit the watchdog routine
    super.shutdown();

    // shutdown the server
    if ( server != null ) {
      server.stop();
    }
  }

  //

  //

  //

  /**
   * Keep the server watchdog busy if there are no components to run.
   * 
   * <p>BTW, This is an example of the simplest runnable component a Loader 
   * can manage. Initialize it, continually calling doWork() while the loader
   * is running then call terminate() when the loader shuts down.
   */
  private class Wedge extends AbstractManagedComponent implements ManagedComponent {

    @Override
    public void initialize() {
      setIdleWait( 5000 );
      setIdle( true );
    }




    @Override
    public void doWork() {}




    @Override
    public void terminate() {}

  }

}
