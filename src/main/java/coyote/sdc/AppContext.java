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
package coyote.sdc;

/**
 * This is a static fixture in the application where all the components can 
 * coordinate their activities.
 * 
 * <p>There is a processor which performs housekeeping and it may die and be 
 * reloaded by the Loader (WebServer). This allows any of those instances to 
 * obtain current references to critical components in the server instance.
 * 
 * <p>Each request to the system results in a new handler being created and an 
 * associated thread. All those handlers and threads need to have a single 
 * location to obtain instance data. This fixture is that location. 
 * 
 */
public class AppContext {

}
