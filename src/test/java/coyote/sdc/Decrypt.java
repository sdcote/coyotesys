/**
 * 
 */
package coyote.sdc;

import coyote.commons.CipherUtil;


/**
 * 
 *
 */
public class Decrypt {

  /**
   * @param args
   */
  public static void main( String[] args ) {
    if ( args.length > 0 ) {
      String cleartext = CipherUtil.decrypt( args[0] );
      System.out.println( "Result:" + cleartext );
    } else {
      System.out.println( "Nothing to process" );
    }

  }

}
