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

import coyote.loader.cfg.Config;
import coyote.loader.component.AbstractManagedComponent;
import coyote.loader.component.ManagedComponent;
import coyote.loader.log.Log;


/**
 * This is a general purpose component for our handlers.
 * 
 * <p>The loader/server loads this component and manages it's life cycle. If it
 * ever detects that it is not active, it will terminate it, and create a new 
 * instance running.
 * 
 * <p>All components have a reference to its loader and can perform operations 
 * using the loader as its configuration point.
 */
public class Processor extends AbstractManagedComponent implements ManagedComponent {
  private static final String INITIALIZING = "Initializing";
  private static final String INITIALIZED = "Initialized";
  private static final String RUNNING = "Running";
  private static final String PARKED = "Parked";
  private static final String TERMINATED = "Terminated";
  private static final String TERMINATING = "Terminating";

  private volatile String hostname = null;




  public Processor() {}




  /**
   * Called just before we enter the main run loop.
   * 
   * @see coyote.loader.thread.ThreadJob#initialize()
   */
  @Override
  public void initialize() {
    loader.getStats().setState( getClass().getSimpleName(), INITIALIZING );

    // Make sure to inform operations that this processor is running
    Log.debug( this.getClass().getSimpleName() + " initialized" );

    // pause 5 seconds between calls to doWork()
    setIdleWait( 5000 );

    // Start out idling
    setIdle( true );

    // maybe we should initialize items configured in the AppContext?
    
    // TODO set a reference in the fixture so other components in
    loader.getStats().setState( getClass().getSimpleName(), INITIALIZED );
  }




  @Override
  public void setConfiguration( Config config ) {
    super.setConfiguration( config );

    // what should we do?
    
    //mayhaps we should configure the static context?
  }




  /**
   * This is the main, reentrant method that is called while in the 
   * main run loop.
   * 
   * @see coyote.loader.thread.ThreadJob#doWork()
   */
  @Override
  public void doWork() {
    loader.getStats().setState( getClass().getSimpleName(), RUNNING );

    // This performs expensive DNS lookup for the initial calls to the 
    // statistics board in a separate thread so as not to delay loading or
    // the initial call to the statsboard hostname lookup functions.
    if ( hostname == null ) {
      hostname = loader.getStats().getHostname();
      if ( hostname == null )
        hostname = "unknown";
    }

    // maybe clear out the frequency tables
    
    // maybe clear our old sessions
    
    // maybe publish logs somewhere?
	
	// This is a good place for tripwire detection, making sure the deployment 
	// has not been touched
    
    // increment a counter showing how many times this component was run
    loader.getStats().increment( getClass().getSimpleName() + ":Runs" );

    loader.getStats().setState( getClass().getSimpleName(), PARKED );
  }




  /**
   * Called after the main run loop is exited, performs any resource clean up.
   * 
   * @see coyote.loader.thread.ThreadJob#terminate()
   */
  @Override
  public void terminate() {
    loader.getStats().setState( getClass().getSimpleName(), TERMINATING );
    // TODO: remove the reference in the fixture so we can get garbage collected. If we are restarted, other components will know to wait for a new reference.
    loader.getStats().setState( getClass().getSimpleName(), TERMINATED );
  }

}
