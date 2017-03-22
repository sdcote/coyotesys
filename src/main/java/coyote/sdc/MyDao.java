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
 * This is the Data Access Object for this application.
 * 
 * <p>There should only be one instance of this class in the runtime, and it is 
 * synchronized at the class level so threads to not interfere with each other 
 * using the embedded H2 database.
 */
public class MyDao {
  
  private static MyDao instance = null;




  private MyDao() {

  }




  public static synchronized MyDao getInstance() {
    if ( instance == null ) {
      instance = new MyDao();
    }
    return instance;
  }
  
  

}
