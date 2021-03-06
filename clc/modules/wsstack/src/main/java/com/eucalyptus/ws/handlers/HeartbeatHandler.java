/*******************************************************************************
 *Copyright (c) 2009 Eucalyptus Systems, Inc.
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, only version 3 of the License.
 * 
 * 
 * This file is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program. If not, see <http://www.gnu.org/licenses/>.
 * 
 * Please contact Eucalyptus Systems, Inc., 130 Castilian
 * Dr., Goleta, CA 93101 USA or visit <http://www.eucalyptus.com/licenses/>
 * if you need additional information or have any questions.
 * 
 * This file may incorporate work covered under the following copyright and
 * permission notice:
 * 
 * Software License Agreement (BSD License)
 * 
 * Copyright (c) 2008, Regents of the University of California
 * All rights reserved.
 * 
 * Redistribution and use of this software in source and binary forms, with
 * or without modification, are permitted provided that the following
 * conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. USERS OF
 * THIS SOFTWARE ACKNOWLEDGE THE POSSIBLE PRESENCE OF OTHER OPEN SOURCE
 * LICENSED MATERIAL, COPYRIGHTED MATERIAL OR PATENTED MATERIAL IN THIS
 * SOFTWARE, AND IF ANY SUCH MATERIAL IS DISCOVERED THE PARTY DISCOVERING
 * IT MAY INFORM DR. RICH WOLSKI AT THE UNIVERSITY OF CALIFORNIA, SANTA
 * BARBARA WHO WILL THEN ASCERTAIN THE MOST APPROPRIATE REMEDY, WHICH IN
 * THE REGENTS’ DISCRETION MAY INCLUDE, WITHOUT LIMITATION, REPLACEMENT
 * OF THE CODE SO IDENTIFIED, LICENSING OF THE CODE SO IDENTIFIED, OR
 * WITHDRAWAL OF THE CODE CAPABILITY TO THE EXTENT NEEDED TO COMPLY WITH
 * ANY SUCH LICENSES OR RIGHTS.
 *******************************************************************************/
package com.eucalyptus.ws.handlers;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.util.List;

import org.apache.log4j.Logger;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineCoverage;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelHandler;
import org.jboss.netty.channel.WriteCompletionEvent;
import org.jboss.netty.handler.codec.http.DefaultHttpResponse;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpMethod;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;

import com.eucalyptus.auth.util.Hashes;
import com.eucalyptus.auth.util.SslSetup;
import com.eucalyptus.bootstrap.Component;
import com.eucalyptus.bootstrap.SystemBootstrapper;
import com.eucalyptus.config.ComponentConfiguration;
import com.eucalyptus.config.Configuration;
import com.eucalyptus.config.RemoteConfiguration;
import com.eucalyptus.util.LogUtil;
import com.eucalyptus.util.NetworkUtil;
import com.eucalyptus.ws.BindingException;
import com.eucalyptus.ws.MappingHttpRequest;
import com.eucalyptus.ws.MappingHttpResponse;
import com.eucalyptus.ws.binding.BindingManager;
import com.eucalyptus.ws.handlers.soap.AddressingHandler;
import com.eucalyptus.ws.handlers.soap.SoapHandler;
import com.eucalyptus.ws.handlers.wssecurity.InternalWsSecHandler;
import com.eucalyptus.ws.stages.UnrollableStage;
import com.google.common.collect.Lists;

import edu.ucsb.eucalyptus.msgs.ComponentType;
import edu.ucsb.eucalyptus.msgs.HeartbeatComponentType;
import edu.ucsb.eucalyptus.msgs.HeartbeatType;

@ChannelPipelineCoverage( "one" )
public class HeartbeatHandler extends SimpleChannelHandler implements UnrollableStage {
  private static Logger  LOG         = Logger.getLogger( HeartbeatHandler.class );
  private Channel        channel;
  private static boolean initialized = false;
  private static List<String> initializedComponents = Lists.newArrayList( );
  
  public HeartbeatHandler( ) {
    super( );
    initialized = true;
  }
  
  public HeartbeatHandler( Channel channel ) {
    super( );
    this.channel = channel;
  }
  
  @Override
  public void handleDownstream( ChannelHandlerContext ctx, ChannelEvent e ) throws Exception {
    ctx.sendDownstream( e );
  }
  
  private void handleInitialize( ChannelHandlerContext ctx, MappingHttpRequest request ) throws IOException, SocketException {
    InetSocketAddress addr = ( InetSocketAddress ) ctx.getChannel( ).getRemoteAddress( );
    LOG.info( LogUtil.subheader( "Using " + addr.getHostName( ) + " as the database address." ) );
    Component.db.setHostAddress( addr.getHostName( ) );
    Component.db.markEnabled( );
    Component.dns.setHostAddress( addr.getHostName( ) );
    Component.eucalyptus.setHostAddress( addr.getHostName( ) );
    Component.cluster.setHostAddress( addr.getHostName( ) );
    Component.jetty.setHostAddress( addr.getHostName( ) );
    HeartbeatType msg = ( HeartbeatType ) request.getMessage( );
    LOG.info( LogUtil.header( "Got heartbeat event: " + LogUtil.dumpObject( msg ) ) );
    for ( HeartbeatComponentType component : msg.getComponents( ) ) {
      LOG.info( LogUtil.subheader( "Registering local component: " + LogUtil.dumpObject( component ) ) );
      System.setProperty( "euca." + component.getComponent( ) + ".name", component.getName( ) );
      Component.valueOf( component.getComponent( ) ).markLocal( );
      //FIXME: this is needed because we can't dynamically change the mule config, so we need to disable at init time and hup when a new component is loaded.
      initializedComponents.add( component.getComponent( ) );
    }
    //FIXME: this is needed because we can't dynamically change the mule config, so we need to disable at init time and hup when a new component is loaded.
    if( !initializedComponents.contains( Component.storage.name( ) ) ) {
      Component.storage.markDisabled( );
    }
    //FIXME: this is needed because we can't dynamically change the mule config, so we need to disable at init time and hup when a new component is loaded.
    if( !initializedComponents.contains( Component.walrus.name( ) ) ) {
      Component.walrus.markDisabled( );
    }
    System.setProperty( "euca.db.password", Hashes.getHexSignature( ) );
    System.setProperty( "euca.db.url", Component.db.getUri( ).toASCIIString( ) );
    boolean foundDb = false;
    try {
      foundDb = NetworkUtil.testReachability( addr.getHostName( ) );
      LOG.debug( "Initializing SSL just in case: " + SslSetup.class );
      foundDb = true;
    } catch ( Throwable e ) {
      foundDb = false;
    }
    if ( foundDb ) {
      HttpResponse response = new DefaultHttpResponse( request.getProtocolVersion( ), HttpResponseStatus.OK );
      ChannelFuture writeFuture = ctx.getChannel( ).write( response );
      writeFuture.addListener( ChannelFutureListener.CLOSE );
      initialized = true;
      if ( this.channel != null ) {
        this.channel.close( );
      }
    } else {
      HttpResponse response = new DefaultHttpResponse( request.getProtocolVersion( ), HttpResponseStatus.NOT_ACCEPTABLE );
      ChannelFuture writeFuture = ctx.getChannel( ).write( response );
      writeFuture.addListener( ChannelFutureListener.CLOSE );
    }
  }
  
  @Override
  public String getStageName( ) {
    return "heartbeat";
  }
  
  @Override
  public void unrollStage( ChannelPipeline pipeline ) {
    pipeline.addLast( "hb-get-handler", new SimpleHeartbeatHandler( ) );
    pipeline.addLast( "deserialize", new SoapMarshallingHandler( ) );
    try {
      pipeline.addLast( "ws-security", new InternalWsSecHandler( ) );
    } catch ( GeneralSecurityException e ) {
      LOG.error( e, e );
    }
    pipeline.addLast( "ws-addressing", new AddressingHandler( ) );
    pipeline.addLast( "build-soap-envelope", new SoapHandler( ) );
    try {
      pipeline.addLast( "binding", new BindingHandler( BindingManager.getBinding( "msgs_eucalyptus_ucsb_edu" ) ) );
    } catch ( BindingException e ) {
      LOG.error( e, e );
    }
    pipeline.addLast( "heartbeat", new HeartbeatHandler( ) );
  }
  
  @ChannelPipelineCoverage( "one" )
  public static class SimpleHeartbeatHandler extends SimpleChannelHandler {
    
    @Override
    public void messageReceived( ChannelHandlerContext ctx, MessageEvent e ) throws Exception {
      if ( e.getMessage( ) instanceof HttpRequest && HttpMethod.GET.equals( ( ( HttpRequest ) e.getMessage( ) ).getMethod( ) ) ) {
        HttpRequest request = ( HttpRequest ) e.getMessage( );
        HttpResponse response = new DefaultHttpResponse( request.getProtocolVersion( ), HttpResponseStatus.OK );
        String resp = "";
        for ( Component c : Component.values( ) ) {
          resp += String.format( "name=%-20.20s enabled=%-10.10s local=%-10.10s initialized=%-10.10s\n", c.name( ),
                                 c.isEnabled( ), c.isLocal( ), c.isInitialized( ) );
        }
        ChannelBuffer buf = ChannelBuffers.copiedBuffer( resp.getBytes( ) );
        response.setContent( buf );
        response.addHeader( HttpHeaders.Names.CONTENT_LENGTH, String.valueOf( buf.readableBytes( ) ) );
        response.addHeader( HttpHeaders.Names.CONTENT_TYPE, "text/plain; charset=UTF-8" );
        ChannelFuture writeFuture = ctx.getChannel( ).write( response );
        writeFuture.addListener( ChannelFutureListener.CLOSE );
      } else {
        ctx.sendUpstream( e );
      }
    }
    
    @Override
    public void exceptionCaught( ChannelHandlerContext ctx, ExceptionEvent e ) throws Exception {
      e.getFuture( ).addListener( ChannelFutureListener.CLOSE );
      super.exceptionCaught( ctx, e );
    }
    
  }
  
  @Override
  public void exceptionCaught( ChannelHandlerContext ctx, ExceptionEvent e ) throws Exception {
    e.getFuture( ).addListener( ChannelFutureListener.CLOSE );
    super.exceptionCaught( ctx, e );
  }
  
  @Override
  public void messageReceived( ChannelHandlerContext ctx, MessageEvent e ) throws Exception {
    Object message = ( ( MessageEvent ) e ).getMessage( );
    if ( message instanceof MappingHttpRequest ) {
      MappingHttpRequest request = ( ( MappingHttpRequest ) message );
      if ( HttpMethod.GET.equals( request.getMethod( ) ) ) {
        handleGet( ctx, request );
      } else if ( !initialized ) {
        handleInitialize( ctx, request );
      } else if ( request.getMessage( ) instanceof HeartbeatType ) {
        handleHeartbeat( request );
      } else {
        ChannelFuture writeFuture = ctx.getChannel( ).write(
                                                             new DefaultHttpResponse( request.getProtocolVersion( ),
                                                               HttpResponseStatus.NOT_ACCEPTABLE ) );
        writeFuture.addListener( ChannelFutureListener.CLOSE );
      }
    } else {
      super.messageReceived( ctx, e );
    }
  }
  
  private void handleGet( ChannelHandlerContext ctx, MappingHttpRequest request ) {
    MappingHttpResponse response = new MappingHttpResponse( request.getProtocolVersion( ), HttpResponseStatus.OK );
    String resp = "";
    for ( Component c : Component.values( ) ) {
      resp += String.format( "name=%-20.20s enabled=%-10.10s local=%-10.10s initialized=%-10.10s\n", c.name( ),
                             c.isEnabled( ), c.isLocal( ), c.isInitialized( ) );
    }
    ChannelBuffer buf = ChannelBuffers.copiedBuffer( resp.getBytes( ) );
    response.setContent( buf );
    response.addHeader( HttpHeaders.Names.CONTENT_LENGTH, String.valueOf( buf.readableBytes( ) ) );
    response.addHeader( HttpHeaders.Names.CONTENT_TYPE, "text/plain; charset=UTF-8" );
    ChannelFuture writeFuture = ctx.getChannel( ).write( response );
    writeFuture.addListener( ChannelFutureListener.CLOSE );
  }
  
  private void handleHeartbeat( MappingHttpRequest request ) throws URISyntaxException {
    HeartbeatType hb = ( HeartbeatType ) request.getMessage( );
    //FIXME: this is needed because we can't dynamically change the mule config, so we need to disable at init time and hup when a new component is loaded.
    List<String> registeredComponents = Lists.newArrayList( );
    for ( HeartbeatComponentType component : hb.getComponents( ) ) {
      if( !initializedComponents.contains( component.getComponent( ) ) ) {
        System.exit(123);//HUP
      }
      registeredComponents.add( component.getComponent( ) );
    }
    if( !registeredComponents.containsAll( initializedComponents ) ) {
      System.exit(123);//HUP
    }
    //FIXME: end.
    for ( ComponentType startedComponent : hb.getStarted( ) ) {
      Component c = Component.valueOf( startedComponent.getComponent( ) );
      try {
        if ( Component.walrus.equals( c ) ) {
          ComponentConfiguration config = Configuration.getWalrusConfiguration( startedComponent.getName( ) );
          Configuration.fireStartComponent( config );
        }
        if ( Component.storage.equals( c ) ) {
          ComponentConfiguration config = Configuration.getStorageControllerConfiguration( startedComponent.getName( ) );
          Configuration.fireStartComponent( config );
        }
      } catch ( Exception e1 ) {
        LOG.debug( e1, e1 );
      }
    }
    for ( ComponentType stoppedComponent : hb.getStopped( ) ) {
      URI uri = new URI( stoppedComponent.getUri( ) );
      Component c = Component.valueOf( stoppedComponent.getComponent( ) );
      try {
        if ( Component.walrus.equals( c ) ) {
          Configuration.fireStopComponent( new RemoteConfiguration( c, uri ) );
        }
        if ( Component.storage.equals( c ) ) {
          Configuration.fireStopComponent( new RemoteConfiguration( c, uri ) );
        }
      } catch ( Exception e1 ) {
        LOG.debug( e1, e1 );
      }
    }
  }
  
  @Override
  public void writeComplete( ChannelHandlerContext ctx, WriteCompletionEvent e ) throws Exception {
    super.writeComplete( ctx, e );
  }
  
}
