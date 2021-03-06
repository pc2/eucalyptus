package com.eucalyptus.cluster.handlers;

import org.apache.log4j.Logger;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelPipelineCoverage;
import org.jboss.netty.channel.MessageEvent;

import com.eucalyptus.cluster.Cluster;
import com.eucalyptus.cluster.event.NewClusterEvent;
import com.eucalyptus.cluster.event.TeardownClusterEvent;
import com.eucalyptus.cluster.util.ClusterUtil;
import com.eucalyptus.event.Event;
import com.eucalyptus.event.GenericEvent;
import com.eucalyptus.util.LogUtil;
import com.eucalyptus.ws.BindingException;
import com.eucalyptus.ws.MappingHttpResponse;

import edu.ucsb.eucalyptus.msgs.GetKeysResponseType;
import edu.ucsb.eucalyptus.msgs.GetKeysType;

@ChannelPipelineCoverage("one")
public class ClusterCertificateHandler extends AbstractClusterMessageDispatcher {
  private static Logger LOG = Logger.getLogger( ClusterCertificateHandler.class );
  private boolean verified = false;
  public ClusterCertificateHandler( Cluster cluster ) throws BindingException {
    super( cluster, false );
  }

  
  public void trigger( ) {
    this.write( new GetKeysType( "self" ) );
    if( this.verified ) {
//      for( String s : this.getCluster( ).getNodeTags( ) ) {
//        LOG.debug( "Querying all known service tags:" );
//TODO: enable verifying node certificates
//        this.write( new GetKeysType( this.makeInsecure( s ) ) );
//      }
    }
  }

  @Override
  public void advertiseEvent( Event event ) {
  }

  @SuppressWarnings( "unchecked" )
  @Override
  public void fireEvent( Event event ) {
    if ( this.timedTrigger( event ) ) {
      this.trigger( );
    } else if ( event instanceof GenericEvent ) {
      GenericEvent<Cluster> g = (GenericEvent<Cluster>) event;
      if( !g.matches( this.getCluster( ) ) ) {
        return;
      }
      if( g instanceof NewClusterEvent && !this.verified ) {
        this.trigger();
      } else if ( event instanceof TeardownClusterEvent ) {
        this.verified = false;
        try {
          ClusterUtil.deregisterClusterStateHandler( this.getCluster( ), new NetworkStateHandler( this.getCluster( ) ) );
          ClusterUtil.deregisterClusterStateHandler( this.getCluster( ), new AddressStateHandler( this.getCluster( ) ) );
          ClusterUtil.deregisterClusterStateHandler( this.getCluster( ), new LogStateHandler( this.getCluster( ) ) );
          ClusterUtil.deregisterClusterStateHandler( this.getCluster( ), new ResourceStateHandler( this.getCluster( ) ) );
          ClusterUtil.deregisterClusterStateHandler( this.getCluster( ), new VmStateHandler( this.getCluster( ) ) );
        } catch ( Exception e ) {
          LOG.error( e, e );
        }
      }
    } else {
      LOG.debug( "Ignoring event which doesn't belong to me: " + LogUtil.dumpObject( event ) );
    }
  }

  @Override
  public void upstreamMessage( ChannelHandlerContext ctx, MessageEvent e ) {
    if( e.getMessage( ) instanceof MappingHttpResponse ) {
      MappingHttpResponse resp = (MappingHttpResponse) e.getMessage( );
      GetKeysResponseType msg = (GetKeysResponseType) resp.getMessage( );
      boolean certs = ClusterUtil.checkCerts( msg, this.getCluster( ) );
      if( certs && !this.verified ) {
        try {
          ClusterUtil.registerClusterStateHandler( this.getCluster( ), new NetworkStateHandler( this.getCluster( ) ) );
          ClusterUtil.registerClusterStateHandler( this.getCluster( ), new LogStateHandler( this.getCluster( ) ) );
          ClusterUtil.registerClusterStateHandler( this.getCluster( ), new ResourceStateHandler( this.getCluster( ) ) );
          ClusterUtil.registerClusterStateHandler( this.getCluster( ), new VmStateHandler( this.getCluster( ) ) );
        } catch ( Exception e1 ) {
          LOG.error( e1, e1 );
        }
        LOG.info( LogUtil.header( "Starting threads for cluster: " + this.getCluster( ) ) );
        this.verified = true;
      } 
    } else {
      LOG.info( "Received unknown message type. " + e.getMessage( ) );
    }    
  }

  
  
}
