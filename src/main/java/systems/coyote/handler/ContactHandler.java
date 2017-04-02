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

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.mail.Message;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import coyote.commons.CipherUtil;
import coyote.commons.StringUtil;
import coyote.commons.network.MimeType;
import coyote.commons.network.http.HTTPD;
import coyote.commons.network.http.IHTTPSession;
import coyote.commons.network.http.Response;
import coyote.commons.network.http.ResponseException;
import coyote.commons.network.http.Status;
import coyote.commons.network.http.handler.UriResource;
import coyote.commons.network.http.handler.UriResponder;
import coyote.commons.security.OperationFrequency;
import coyote.loader.BootStrap;
import coyote.loader.cfg.Config;
import coyote.loader.log.Log;
import systems.coyote.WebServer;


/**
 * This handles the "contact us" form.
 * 
 * <p>Because this is a very expensive operation which can affect many other 
 * resources, a significant amout of scrutiny is affored to the request 
 * helping to insure the operation is not abused. Specifically, all requests 
 * are checked against a DoS table to track how frequently a particular 
 * address make this request. If it exceeds the configured limits, the 
 * operation fails. If it fails more than the configured limit, the IP address 
 * is black-listed from the server entirely.
 * 
 * <p>The logs should be checked regularly for repeat offenders and added to 
 * the server blacklist configuration for permanent ban from the site.
 */
public class ContactHandler extends AbstractJsonHandler implements UriResponder {

  private static final String CLASSNAME = ContactHandler.class.getSimpleName();
  private static final String DOS_TABLE_KEY = CLASSNAME + "DOS.TABLE";
  private static final String DURATION = "Window";
  private static final String LIMIT = "Limit";
  private static final String BLACKLIST_LIMIT = "BlacklistLimit";
  private static final short DEFAULT_LIMIT = 2; // limit contact requests to 2
  private static final long DEFAULT_DURATION = 60 * 60 * 1000; // per hour
  private static final String DENIAL_OF_SERVICE_MESSGE = "Frequent requests from this address for this operation: Tracking Suspected DoS Attempt";
  private static final String BREACH_MAP_KEY = CLASSNAME + "BREACH.MAP";
  private static final int DEFAULT_BREACH_THRESHOLD = 3; // three strikes and you're out
  private static final long ONE_DAY = 24 * 60 * 60 * 1000;// one day in milliseconds
  private String username;
  private String password;
  private String sender;
  private String receiver;
  private String mailHost;
  private String mailPort;
  private String subject;




  /**
   * This does not have to be a fast response, 1-3 seconds should be tolerable 
   * for the type of operation being requested.
   */
  @Override
  public Response post( UriResource uriResource, Map<String, String> urlParams, IHTTPSession session ) {
    WebServer loader = uriResource.initParameter( 0, WebServer.class );
    Config config = uriResource.initParameter( 1, Config.class );

    // parse the request body, populating any request parameters (from the 
    // submitted form) and any file chunks, although there should be none
    try {
      parseBody( session );
    } catch ( final IOException ioe ) {
      return Response.createFixedLengthResponse( Status.INTERNAL_ERROR, MimeType.TEXT.getType(), "Problems parsing request body: " + ioe.getMessage() );
    } catch ( final ResponseException re ) {
      return Response.createFixedLengthResponse( re.getStatus(), MimeType.TEXT.getType(), re.getMessage() );
    }

    // This is a shared context for all components of this loader (WebServer) to share
    synchronized( loader.getContext() ) {
      // use it to store a DoS table to record how often someone tries to contact us
      OperationFrequency dosTable;
      Object obj = loader.getContext().get( DOS_TABLE_KEY );
      if ( obj != null && obj instanceof OperationFrequency ) {
        dosTable = (OperationFrequency)obj;
      } else {
        dosTable = new OperationFrequency();

        short limit = DEFAULT_LIMIT;
        try {
          limit = config.getShort( LIMIT );
        } catch ( Exception ignore ) {}

        long duration = DEFAULT_DURATION;
        try {
          duration = config.getLong( DURATION );
        } catch ( Exception ignore ) {}

        dosTable.setLimit( limit );
        dosTable.setDuration( duration );
        loader.getContext().set( DOS_TABLE_KEY, dosTable );
      }

      // allows X contacts in Y milliseconds
      if ( dosTable.check( session.getRemoteIpAddress() ) ) {

        configure( config );
        String mailText = generateMessage( session.getParms() );

        // it might be a good time to clean up the DoS table, should not take 
        // too long as not many requests are expected to this resource.
        dosTable.expire( ONE_DAY );

        if ( sendMail( mailText ) ) {
          return Response.createFixedLengthResponse( getStatus(), getMimeType(), getText() );
        } else {
          Log.warn( "Could not send contact message - \"" + mailText + "\"" );
          results.put( "error", "Could not send contact message" );
          return Response.createFixedLengthResponse( Status.INTERNAL_ERROR, getMimeType(), getText() );
        }

      } else {
        String remoteAddress = session.getRemoteIpAddress().toString();
        Log.append( HTTPD.EVENT, "DoS suspected from " + remoteAddress );

        obj = loader.getContext().get( BREACH_MAP_KEY );
        Map<String, Integer> breachMap;
        if ( obj != null && obj instanceof Map<?, ?> ) {
          breachMap = (Map<String, Integer>)obj;
        } else {
          breachMap = new HashMap<String, Integer>();
          loader.getContext().set( BREACH_MAP_KEY, breachMap );
        }
        int breachcount = 1;
        if ( breachMap.containsKey( remoteAddress ) ) {
          breachcount = breachMap.get( remoteAddress );
          breachMap.put( remoteAddress, ++breachcount );
        } else {
          breachMap.put( remoteAddress, breachcount );
        }
        Log.append( HTTPD.EVENT, "DoS threshhold breached " + breachcount + " times by " + remoteAddress );

        // On X violations per IP, log the breach and add the IP address to the 
        // server blacklist.
        int breachThreshold = DEFAULT_BREACH_THRESHOLD;
        try {
          breachThreshold = config.getInt( BLACKLIST_LIMIT );
        } catch ( Exception ignore ) {}

        if ( breachcount >= breachThreshold ) {
          Log.append( HTTPD.EVENT, "DoS detected from " + remoteAddress + " due to breach count exceeding threshold of " + breachThreshold + " breaches - black-listing host from server." );
          loader.blacklist( session.getRemoteIpAddress() );
        }

        // if exceeded our operational frequency limit, pause for a few seconds before returning an error message
        //try { Thread.sleep( 5 * 1000 ); } catch ( InterruptedException ignore ) {}

        return Response.createFixedLengthResponse( Status.FORBIDDEN, MimeType.TEXT.getType(), DENIAL_OF_SERVICE_MESSGE );
      }

    } // synchronized on context

  }




  /**
   * @param parms
   * @return
   */
  private String generateMessage( Map<String, String> params ) {
    StringBuffer b = new StringBuffer();
    for ( String key : params.keySet() ) {
      b.append( "'" + key + "':'" + params.get( key ) + "'" );
    }
    return b.toString();
  }




  /**
   * 
   */
  private void configure( Config config ) {
    username = config.getString( "Username" );
    if ( StringUtil.isBlank( username ) ) {
      String cipherText = config.getString( "EncryptedUsername" );
      if ( StringUtil.isNotBlank( cipherText ) ) {
        username = BootStrap.decrypt( cipherText );
      }
    }

    password = config.getString( "Password" );
    if ( StringUtil.isBlank( password ) ) {
      String cipherText = config.getString( "EncryptedPassword" );
      if ( StringUtil.isNotBlank( cipherText ) ) {
        password = BootStrap.decrypt( cipherText );
      }
    }

    sender = config.getString( "Sender" );
    if ( StringUtil.isBlank( sender ) ) {
      String cipherText = config.getString( "EncryptedSender" );
      if ( StringUtil.isNotBlank( cipherText ) ) {
        sender = BootStrap.decrypt( cipherText );
      }
    }

    receiver = config.getString( "Receiver" );
    if ( StringUtil.isBlank( receiver ) ) {
      String cipherText = config.getString( "EncryptedReceiver" );
      if ( StringUtil.isNotBlank( cipherText ) ) {
        receiver = BootStrap.decrypt( cipherText );
      }
    }

    mailHost = config.getString( "Host" );
    mailPort = config.getString( "Port" );
    subject = config.getString( "Subject" );
    if ( StringUtil.isBlank( subject ) ) {
      subject = "Contact Email";
    }

  }




  /**
   * Send an email
   * 
   * @param text the message text to send.
   * 
   * @return true if the email sent sucessfully, false if there were issues
   */
  public boolean sendMail( String text ) {

    Properties props = new Properties();
    props.put( "mail.smtp.auth", "true" );
    props.put( "mail.smtp.starttls.enable", "true" );
    props.put( "mail.smtp.host", mailHost );
    props.put( "mail.smtp.port", mailPort );

    Session session = Session.getDefaultInstance( props, new javax.mail.Authenticator() {
      @Override
      protected PasswordAuthentication getPasswordAuthentication() {
        return new PasswordAuthentication( username, password );
      }
    } );
    try {
      Message message = new MimeMessage( session );
      message.setFrom( new InternetAddress( sender ) );
      message.setRecipients( Message.RecipientType.TO, InternetAddress.parse( receiver ) );
      message.setSubject( subject );
      message.setText( text );
      Transport.send( message );
      return true;
    } catch ( Exception e ) {
      System.out.println( e );
      return false;
    }
  }

}