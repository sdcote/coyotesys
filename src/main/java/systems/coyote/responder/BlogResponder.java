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

import java.net.URL;
import java.util.Map;

import coyote.commons.StringUtil;
import coyote.commons.network.MimeType;
import coyote.commons.network.http.HTTPD;
import coyote.commons.network.http.IHTTPSession;
import coyote.commons.network.http.IStatus;
import coyote.commons.network.http.Response;
import coyote.commons.network.http.Status;
import coyote.commons.network.http.auth.Auth;
import coyote.commons.network.http.responder.DefaultResponder;
import coyote.commons.network.http.responder.Error404Responder;
import coyote.commons.network.http.responder.HTTPDRouter;
import coyote.commons.network.http.responder.Resource;
import coyote.commons.network.http.responder.Responder;
import coyote.loader.cfg.Config;
import coyote.loader.log.Log;
import systems.coyote.WebServer;


/**
 * Retrieves blog articles from content based on a variety of naming
 * conventions.
 *
 * <p>This is designed to be loaded by the server from a configuration file
 * similar to the following:<pre>
 * "Mappings" : {
 *     "blog/(.)+" : { "Class" : "systems.coyote.handler.BlogHandler", "Root":"content/blog" }
 *  }</pre>
 *  The {@code Root} element describes where in the class path the articles
 *  can be found.
 *
 * <p>Basic operation involves retrieving the name of the article from the URI
 * then normalizing it to all lower case and replacing any spaces or %20 with
 * underscores. The normalized name is then used to lookup the resource with
 * the class loader.
 */
@Auth(required = false)
public class BlogResponder extends DefaultResponder implements Responder {

  // The configuration parameter containing the root of the blog articles
  private static final String ROOT = "Root";

  // The default root namespace of our articles
  private static final String DEFAULT_ROOT = "content/blog";

  private static final String INDEX_PAGE = "index.html";

  // The class loader object associated with this Class
  ClassLoader cLoader = this.getClass().getClassLoader();




  /**
   *
   */
  @Override
  public Response get( final Resource resource, final Map<String, String> urlParams, final IHTTPSession session ) {
    resource.initParameter( 0, WebServer.class );
    final Config config = resource.initParameter( 1, Config.class );

    final String baseUri = resource.getUri(); // the regex matcher URL

    String coreRequest = HTTPDRouter.normalizeUri( session.getUri() );

    if ( !baseUri.equals( coreRequest ) ) {
      // find the portion of the URI which differs from the base
      for ( int index = 0; index < Math.min( baseUri.length(), coreRequest.length() ); index++ ) {
        if ( baseUri.charAt( index ) != coreRequest.charAt( index ) ) {
          coreRequest = HTTPDRouter.normalizeUri( coreRequest.substring( index ) );
          break;
        }
      }
    } else {
      //exact match; means the same as requesting /
      coreRequest = "";
    }

    // Retrieve the base directory in the classpath for our search
    String parentdirectory = config.getString( ROOT );
    try {
      if ( StringUtil.isBlank( parentdirectory ) ) {
        parentdirectory = DEFAULT_ROOT;
      }
    } catch ( final Exception e ) {
      Log.append( HTTPD.EVENT, "BlogHandler initialization error: Root Directory: " + e.getMessage() + " - defaulting to '" + DEFAULT_ROOT + "'" );
    }

    // make sure we are configured with a properly formatted parent directory
    if ( !parentdirectory.endsWith( "/" ) ) {
      parentdirectory = parentdirectory.concat( "/" );
    }
    if ( parentdirectory.startsWith( "/" ) ) {
      parentdirectory = parentdirectory.substring( 1 );
    }

    // Normalize the name of the article here

    // remove any path delimiters from the ends of the request
    if ( coreRequest.startsWith( "/" ) ) {
      coreRequest = coreRequest.substring( 1 );
    }
    if ( coreRequest.endsWith( "/" ) ) {
      coreRequest = coreRequest.substring( 0, coreRequest.length() - 1 );
    }

    // convert to lowercase
    coreRequest = coreRequest.toLowerCase();

    // remove any spaces
    coreRequest = coreRequest.replaceAll( "%20", "_" );
    coreRequest = coreRequest.replaceAll( " ", "_" );

    // if the core request is now empty, serve up the blog index page.
    if ( StringUtil.isBlank( coreRequest ) ) {
      coreRequest = INDEX_PAGE;
    }

    // add our configured parent directory to the real request. This is the
    // actual local resource for which we are looking:
    final String localPath = parentdirectory + coreRequest;

    // See if the requested resource exists
    final URL rsc = cLoader.getResource( localPath );

    // if we have no URL, the class loader could not find the resource
    if ( rsc == null ) {
      Log.append( HTTPD.EVENT, "404 NOT FOUND - '" + coreRequest + "' LOCAL: " + localPath );
      return new Error404Responder().get( resource, urlParams, session );
    } else {
      // Success - Found the resource /article
      try {
        return Response.createChunkedResponse( Status.OK, HTTPD.getMimeTypeForFile( localPath ), cLoader.getResourceAsStream( localPath ) );
      } catch ( final Exception ioe ) {
        return Response.createFixedLengthResponse( Status.REQUEST_TIMEOUT, MimeType.TEXT.getType(), null );
      }
    }
  }




  @Override
  public String getMimeType() {
    return MimeType.HTML.getType();
  }




  @Override
  public IStatus getStatus() {
    return Status.OK;
  }




  @Override
  public String getText() {
    return "";
  }

}
