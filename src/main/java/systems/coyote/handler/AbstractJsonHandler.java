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

import coyote.commons.network.MimeType;
import coyote.commons.network.http.IStatus;
import coyote.commons.network.http.Status;
import coyote.commons.network.http.handler.DefaultHandler;
import coyote.commons.network.http.handler.UriResponder;
import coyote.dataframe.DataFrame;
import coyote.dataframe.marshal.JSONMarshaler;


/**
 * This is a common base class for handlers which implement a JSON web service 
 * pattern. 
 */
public abstract class AbstractJsonHandler extends DefaultHandler implements UriResponder {

  protected final DataFrame results = new DataFrame();
  private boolean formattingJson = false;




  /**
   * @return true if we are formatting JSON, false (default) if not.
   */
  public boolean isFormattingJson() {
    return formattingJson;
  }




  /**
   * @param flag true to cause getText() to return formatted JSON, false (default) to represent it in compressed format.
   */
  public void setFormattingJson( boolean flag ) {
    this.formattingJson = flag;
  }




  @Override
  public IStatus getStatus() {
    return Status.OK;
  }




  @Override
  public String getText() {
    if ( formattingJson )
      return JSONMarshaler.toFormattedString( results );
    else
      return JSONMarshaler.marshal( results );
  }




  @Override
  public String getMimeType() {
    return MimeType.JSON.getType();
  }
}
