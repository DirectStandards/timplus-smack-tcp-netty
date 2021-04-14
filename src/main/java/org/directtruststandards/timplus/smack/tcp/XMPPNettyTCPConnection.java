package org.directtruststandards.timplus.smack.tcp;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.InetAddress;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLSession;

import org.directtruststandards.timplus.smack.tcp.codec.ElementEncoder;
import org.directtruststandards.timplus.smack.tcp.codec.XMPPFrameDecoder;
import org.jivesoftware.smack.AbstractXMPPConnection;
import org.jivesoftware.smack.ConnectionConfiguration;
import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.SynchronizationPoint;
import org.jivesoftware.smack.SmackException.ConnectionException;
import org.jivesoftware.smack.SmackException.NotConnectedException;
import org.jivesoftware.smack.SmackException.SecurityRequiredByServerException;
import org.jivesoftware.smack.XMPPException.StreamErrorException;
import org.jivesoftware.smack.compress.packet.Compress;
import org.jivesoftware.smack.compress.packet.Compressed;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.ConnectionConfiguration.DnssecMode;
import org.jivesoftware.smack.ConnectionConfiguration.SecurityMode;
import org.jivesoftware.smack.packet.IQ;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.packet.Nonza;
import org.jivesoftware.smack.packet.Presence;
import org.jivesoftware.smack.packet.Stanza;
import org.jivesoftware.smack.packet.StartTls;
import org.jivesoftware.smack.packet.StreamError;
import org.jivesoftware.smack.packet.StreamOpen;
import org.jivesoftware.smack.sasl.packet.SaslStreamElements;
import org.jivesoftware.smack.sasl.packet.SaslStreamElements.Challenge;
import org.jivesoftware.smack.sasl.packet.SaslStreamElements.SASLFailure;
import org.jivesoftware.smack.sasl.packet.SaslStreamElements.Success;
import org.jivesoftware.smack.sm.packet.StreamManagement.Failed;
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration;
import org.jivesoftware.smack.util.DNSUtil;
import org.jivesoftware.smack.util.PacketParserUtils;
import org.jivesoftware.smack.util.dns.HostAddress;
import org.jivesoftware.smack.util.dns.SmackDaneProvider;
import org.jivesoftware.smack.util.dns.SmackDaneVerifier;
import org.jxmpp.jid.impl.JidCreate;
import org.jxmpp.jid.parts.Resourcepart;
import org.jxmpp.stringprep.XmppStringprepException;
import org.jxmpp.util.XmppStringUtils;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.compression.JdkZlibDecoder;
import io.netty.handler.codec.compression.JdkZlibEncoder;
import io.netty.handler.codec.compression.ZlibWrapper;
import io.netty.handler.codec.string.StringEncoder;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

/**
 * Based off of the XMPPTCPConnection class, this implementation utilizes Netty as the
 * underlying networking framework.  The goal is to allow multiple connections (hundreds or thousands)
 * to execute within a single JVM without exhausting the available threads on a system.  This implementation
 * allocates up to NumberOfCores / 2 threads for processing incoming XMPP messages.  Depending on the underlying
 * OS and JVM implementations, number of cores may take into consideration hyper-threading which would
 * effectively double the number of cores. 
 * 
 * @author Greg Meyer
 *
 */
public class XMPPNettyTCPConnection extends AbstractXMPPConnection
{
	protected static final int FALLBACK_EVENT_LOOP_THREADS = 4;
	
	protected static EventLoopGroup eventLoopGrp;
	
	private static final Logger LOGGER = Logger.getLogger(XMPPNettyTCPConnection.class.getName());
	
	protected SslHandler sslHandler;
	
	protected ChannelHandler compressionDecoder;
	
	protected ChannelHandler compressionEncoder;
	
	protected Channel connectionChannel;
	
    private final SynchronizationPoint<Exception> initialOpenStreamSend = new SynchronizationPoint<>(
            this, "initial open stream element send to server");
	
    private final SynchronizationPoint<Exception> closingStreamReceived = new SynchronizationPoint<>(
            this, "stream closing element received");
    
    private final SynchronizationPoint<XMPPException> maybeCompressFeaturesReceived = new SynchronizationPoint<XMPPException>(
            this, "stream compression feature");
    
    private final SynchronizationPoint<SmackException> compressSyncPoint = new SynchronizationPoint<>(
            this, "stream compression");
    
    
	static 
	{
		final int numProcessors = Runtime.getRuntime().availableProcessors();
		int numThreads = (numProcessors < 1) ?  FALLBACK_EVENT_LOOP_THREADS : numProcessors / 2;
		
		// create a default event loop group
		eventLoopGrp = new NioEventLoopGroup(numThreads);
		
		try
		{
			/*
			 * Override the CACHED_EXECUTOR_SERVICE executor.  The CACHED_EXECUTOR_SERVICE is an open ended
			 * list of threads that could cause resource exhaustion in highly concurrent environments.
			 * The override implementation will fix the thread count to the same number of threads 
			 * for the Netty event loop group.   
			 */
			final Field field = AbstractXMPPConnection.class.getDeclaredField("CACHED_EXECUTOR_SERVICE");
			
			field.setAccessible(true);
			
		    final Field modifiersField = Field.class.getDeclaredField("modifiers");
		    modifiersField.setAccessible(true);
		    modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);
			
			final ExecutorService NETTYSMACK_CACHED_EXECUTOR_SERVICE = Executors.newFixedThreadPool(numThreads, new ThreadFactory() 
		    {
		        @Override
		        public Thread newThread(Runnable runnable) 
		        {
		            final Thread thread = new Thread(runnable);
		            thread.setName("Netty Smack Cached Executor");
		            thread.setDaemon(true);
		            thread.setUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() 
		            {
		                @Override
		                public void uncaughtException(Thread t, Throwable e) 
		                {
		                    LOGGER.log(Level.WARNING, t + " encountered uncaught exception", e);
		                }
		            });
		            return thread;
		        }
		    });	
			
			field.set(modifiersField, NETTYSMACK_CACHED_EXECUTOR_SERVICE);
		}
		catch (Exception e)
		{
			LOGGER.warning("Failed to override CACHED_EXECUTOR_SERVICE and falling back to default implementation. " 
					+ "This may result in high thread usage if multipel connections are made in the same JVM.");
		}
	}
	
	public XMPPNettyTCPConnection(XMPPTCPConnectionConfiguration config) 
	{
		super(config);
	}
	
    public XMPPNettyTCPConnection(CharSequence jid, String password) throws XmppStringprepException 
    {
        this(XmppStringUtils.parseLocalpart(jid.toString()), password, XmppStringUtils.parseDomain(jid.toString()));
    }

    public XMPPNettyTCPConnection(CharSequence username, String password, String serviceName) throws XmppStringprepException 
    {
        this(XMPPTCPConnectionConfiguration.builder()
        		.setUsernameAndPassword(username, password)
        		.setXmppDomain(JidCreate.domainBareFrom(serviceName))
        		.build());
    }

	@Override
	public boolean isSecureConnection() 
	{
		return sslHandler != null;
	}

	@Override
	protected void sendStanzaInternal(Stanza packet) throws NotConnectedException, InterruptedException 
	{
		this.connectionChannel.writeAndFlush(packet);
		
        if (packet != null) 
        {
            firePacketSendingListeners(packet);
        }
		
	}

	@Override
	public void sendNonza(Nonza element) throws NotConnectedException, InterruptedException 
	{
		this.connectionChannel.writeAndFlush(element);
		
        if (element instanceof Stanza)
        	firePacketSendingListeners((Stanza) element);
		
	}

	@Override
	public boolean isUsingCompression() 
	{
		return compressionDecoder != null && compressionEncoder != null && compressSyncPoint.wasSuccessful();
	}

    protected void maybeEnableCompression() throws SmackException, InterruptedException 
    {
        if (!config.isCompressionEnabled()) 
        {
            return;
        }

        Compress.Feature compression = getFeature(Compress.Feature.ELEMENT, Compress.NAMESPACE);
        if (compression == null) 
        {
            return;
        }
        
        
        for (String method : compression.getMethods())
        {
        	if (method.compareToIgnoreCase("zlib") == 0)
        	{
        		compressionDecoder = new JdkZlibDecoder(ZlibWrapper.ZLIB);
        		compressionEncoder = new JdkZlibEncoder(ZlibWrapper.ZLIB);
        		
        		compressSyncPoint.sendAndWaitForResponseOrThrow(new Compress("zlib"));
        		
        		break;
        	}
        }
        
        if (compressionDecoder == null)
        {
        	LOGGER.warning("Could not enable compression because no matching handler/method pair was found");
        }
        
    }	
	
    protected void installCompressionHandlers(ChannelHandlerContext ctx)
    {
    	final ChannelPipeline pl = ctx.pipeline();
    	
		pl.addBefore("string-encoder", "compress-decoder", compressionEncoder);
		pl.addBefore("xmpp-framedecoder", "compression-decoder" , compressionDecoder);

    }
   
    
	@Override
	protected void connectInternal() throws SmackException, IOException, XMPPException, InterruptedException 
	{
		closingStreamReceived.init();
		
		/*
		 * First close any exist connections
		 */
		
		if (connectionChannel != null)
		{
			connectionChannel.close().sync();
			
			connectionChannel = null;
		}
		
		closingStreamReceived.init();
		
		connectUsingConfiguration();
		
		tlsHandled.checkIfSuccessOrWaitOrThrow();
		
        saslFeatureReceived.checkIfSuccessOrWaitOrThrow();
	}

	@Override
	protected void loginInternal(String username, String password, Resourcepart resource)
			throws XMPPException, SmackException, IOException, InterruptedException 
	{
        final SSLSession sslSession = sslHandler != null ? sslHandler.engine().getSession() : null;
        saslAuthentication.authenticate(username, password, config.getAuthzid(), sslSession);

        maybeCompressFeaturesReceived.checkIfSuccessOrWait();

        maybeEnableCompression();
        
        bindResourceAndEstablishSession(resource);

        afterSuccessfulLogin(false);
		
	}

	@Override
	protected void shutdown() 
	{
		shutdown(false);
	}

	@Override
	public void instantShutdown() 
	{
		shutdown(true);
	}
	
    protected void shutdown(boolean instant) 
    {  		
        if (this.connectionChannel != null)
        {
        	try
        	{
	        	connectionChannel.writeAndFlush("</stream:stream>");      	
	        	
	        	connectionChannel.closeFuture();
        	}
        	catch (Exception e)
        	{
        		LOGGER.log(Level.WARNING, "shutdown", e);
        	}
        }
        
        setWasAuthenticated();
    }
    
    @Override
    protected void initState() 
    {
        super.initState();
        maybeCompressFeaturesReceived.init();
        compressSyncPoint.init();
        initialOpenStreamSend.init();
        
        this.sslHandler = null;
        this.connectionChannel = null;
        this.compressionDecoder = null;
        this.compressionEncoder = null;
    }
    
    protected void setWasAuthenticated() 
    {
        // Never reset the flag if the connection has ever been authenticated
        if (!wasAuthenticated) {
            wasAuthenticated = authenticated;
        }
    }
    
    
	protected void connectUsingConfiguration() throws ConnectionException, IOException, InterruptedException
	{
		final List<HostAddress> failedAddresses = populateHostAddresses();
		
		for (HostAddress hostAddress : hostAddresses)
		{
            final String host = hostAddress.getHost();
            final int port = hostAddress.getPort();
            
            for (final InetAddress inetAddress :  hostAddress.getInetAddresses())
            {
				final Bootstrap b = new Bootstrap();
				b.group(eventLoopGrp)
				.channel(NioSocketChannel.class)
				.option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 5000)
				.handler(new ChannelInitializer<SocketChannel>() 
				{
					@Override
					public void initChannel(SocketChannel ch) throws Exception 
					{
						ChannelPipeline p = ch.pipeline();
						
			
						p.addLast("string-encoder", new StringEncoder());	
						p.addLast(new ElementEncoder());
						

						p.addLast("xmpp-framedecoder", new XMPPFrameDecoder(Integer.MAX_VALUE));
						p.addLast(new StanzaHandler());
						
					}
				});	  
				
				
				
				try
				{
					final ChannelFuture f = b.connect(inetAddress, port);
					
					this.connectionChannel = f.sync().channel();
				}
				catch (Exception e)
				{
					// TODO: Log error
					continue;
				}
				
                this.host = host;
                this.port = port;
                return;
            }
            failedAddresses.add(hostAddress);
		}
		
        // There are no more host addresses to try
        // throw an exception and report all tried
        // HostAddresses in the exception
        throw ConnectionException.from(failedAddresses);
	}
	
	protected class StanzaHandler extends SimpleChannelInboundHandler<ByteBuf>
	{

		@Override
		public void channelActive(ChannelHandlerContext ctx)
		{		
			try
			{
				openStream(ctx);
			}
			catch (Exception e)
			{
				
			}
			initialOpenStreamSend.reportSuccess();
		}
		
		@Override
		protected void channelRead0(ChannelHandlerContext ctx, ByteBuf in) throws Exception 
		{	
			boolean done = false;
			
			byte[] bytes;
			if (!in.hasArray())
			{
				bytes = new byte[in.readableBytes()];
				in.getBytes(in.readerIndex(), bytes);	
			}
			else
				bytes = in.array();
			
			in.readByte();
			
			final InputStream is = new ByteArrayInputStream(bytes);
			
			final Reader reader = new BufferedReader(new InputStreamReader(is, "UTF-8"));
			
			final XmlPullParser parser =  XmlPullParserFactory.newInstance().newPullParser();
			parser.setInput(reader);
	        parser.setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, true);
			
			try
			{
				int eventType = parser.getEventType();
				while (!done)
				{
					switch (eventType)
					{
						case XmlPullParser.START_TAG:
						{
	                        final String name = parser.getName();
	                        switch (name) 
	                        {
	                        	case Message.ELEMENT:
	                        	case IQ.IQ_ELEMENT:
	                        	case Presence.ELEMENT:
	                            {
	                                parseAndProcessStanza(parser);
	                            
	                                break;
	                            }
	                            case "stream":
	                            {
	                            	String reportedServerDomain = parser.getAttributeValue("", "from");
	                            	if (reportedServerDomain != null && !reportedServerDomain.isEmpty())
	                            	{
		                                // We found an opening stream.
		                                if ("jabber:client".equals(parser.getNamespace(null))) {
		                                    streamId = parser.getAttributeValue("", "id");
		                                    assert (config.getXMPPServiceDomain().equals(reportedServerDomain));
		                                }
	                            	}
	                                break;	
	                            }
	                            case "error":
	                            {
	                                StreamError streamError = PacketParserUtils.parseStreamError(parser);
	                                saslFeatureReceived.reportFailure(new StreamErrorException(streamError));

	                                tlsHandled.reportSuccess();
	                                throw new StreamErrorException(streamError);	
	                            }
	                            case "features":
	                            {
	                                parseFeatures(parser);
	                                break;
	                            }
	                            case "failure":
	                            {
	                                String namespace = parser.getNamespace(null);
	                                switch (namespace) {
	                                case "urn:ietf:params:xml:ns:xmpp-tls":

	                                    throw new SmackException("TLS negotiation has failed");
	                                case "http://jabber.org/protocol/compress":

	                                    compressSyncPoint.reportFailure(new SmackException(
	                                                    "Could not establish compression"));
	                                    break;
	                                case SaslStreamElements.NAMESPACE:

	                                    final SASLFailure failure = PacketParserUtils.parseSASLFailure(parser);
	                                    getSASLAuthentication().authenticationFailed(failure);
	                                    break;
	                                }
	                                break;  
	                            }
	                            case "proceed":
	                            {
	                                try {

	                                    proceedTLSReceived(ctx);

	                                    openStream(ctx);
	                                }
	                                catch (Exception e) {
	                                    SmackException smackException = new SmackException(e);
	                                    tlsHandled.reportFailure(smackException);
	                                    throw e;
	                                }
	                                break;	
	                            }
	                            case Challenge.ELEMENT:
	                            {

	                                String challengeData = parser.nextText();
	                                getSASLAuthentication().challengeReceived(challengeData);
	                                break;
	                            }
	                            
	                            case Success.ELEMENT:
	                            {
	                                Success success = new Success(parser.nextText());

	                                openStream(ctx);

	                                getSASLAuthentication().authenticated(success);
	                                break;    
	                            }
	                            case Compressed.ELEMENT:
	                            {

	                                installCompressionHandlers(ctx);

	                                openStream(ctx);
	
	                                compressSyncPoint.reportSuccess();
	                                break;
	                            }
	                            case Failed.ELEMENT:
	                            {

	                                lastFeaturesReceived.reportSuccess();

	                                break;
	                            }
	                            default:
	                            {
	                                LOGGER.warning("Unknown top level stream element: " + name);
	                                break;
	                            }
	                        }
   
							break;
						}
						case XmlPullParser.END_DOCUMENT:
						{
							done = true;
						}
	                    case XmlPullParser.END_TAG:
	                    {
	                        final String endTagName = parser.getName();
	                        if ("stream".equals(endTagName)) 
	                        {
	                            if (!parser.getNamespace().equals("http://etherx.jabber.org/streams")) 
	                            {
	                                LOGGER.warning(XMPPNettyTCPConnection.this +  " </stream> but different namespace " + parser.getNamespace());
	                                break;
	                            }

	                            final boolean connectionWasShutdown = XMPPNettyTCPConnection.this.connectionChannel == null;
	                            closingStreamReceived.reportSuccess();

	                            if (connectionWasShutdown) 
	                            {
	
	                                return;
	                            } 
	                            else 
	                            {

	                                LOGGER.info(XMPPNettyTCPConnection.this
	                                                + " received closing </stream> element."
	                                                + " Server wants to terminate the connection, calling disconnect()");
	                                ASYNC_BUT_ORDERED.performAsyncButOrdered(XMPPNettyTCPConnection.this, new Runnable() 
	                                {
	                                    @Override
	                                    public void run() 
	                                    {
	                                        disconnect();
	                                    }
	                                });
	                            }
	                        }
	                        break;		
	                    }
					}
					
					eventType = parser.next();
				}
			}
			catch (EOFException | XmlPullParserException e)
			{
				// move one
			}
			catch (Exception e)
			{
				//e.printStackTrace();
			}
		}
		
	}
	
	protected void openStream(ChannelHandlerContext ctx) throws Exception
	{
        final CharSequence to = getXMPPServiceDomain();
        CharSequence from = null;
        CharSequence localpart = config.getUsername();
        if (localpart != null) {
            from = XmppStringUtils.completeJidFrom(localpart, to);
        }
        String id = getStreamId();

        sendNonza(new StreamOpen(to, from, id));
	
	}
	
    protected void proceedTLSReceived(ChannelHandlerContext ctx) throws NoSuchAlgorithmException, CertificateException, IOException, 
       NoSuchProviderException, UnrecoverableKeyException, KeyManagementException, SmackException 
    {
        SmackDaneVerifier daneVerifier = null;

        if (config.getDnssecMode() == DnssecMode.needsDnssecAndDane) 
        {
            SmackDaneProvider daneProvider = DNSUtil.getDaneProvider();
            if (daneProvider == null) 
            {
                throw new UnsupportedOperationException("DANE enabled but no SmackDaneProvider configured");
            }
            daneVerifier = daneProvider.newInstance();
            if (daneVerifier == null) 
            {
                throw new IllegalStateException("DANE requested but DANE provider did not return a DANE verifier");
            }
        }

        /*
         * For now, just default a reasonable TLS context that will trust any server
         */
        final SslContext sslCtx = SslContextBuilder.forClient().sslProvider(null)
                .trustManager(InsecureTrustManagerFactory.INSTANCE).build();

        sslHandler = sslCtx.newHandler(ctx.channel().alloc(), this.host, this.port);
        sslHandler.engine().setEnabledProtocols(new String[] {"TLSv1.2"});
               
        ctx.pipeline().addFirst("sslHandler", sslHandler);

    }	
    
    @Override
    protected void afterFeaturesReceived() throws NotConnectedException, InterruptedException, SecurityRequiredByServerException 
    {
        final StartTls startTlsFeature = getFeature(StartTls.ELEMENT, StartTls.NAMESPACE);
        if (startTlsFeature != null) 
        {
            if (startTlsFeature.required() && config.getSecurityMode() == SecurityMode.disabled) 
            {
                final SecurityRequiredByServerException smackException = new SecurityRequiredByServerException();
                tlsHandled.reportFailure(smackException);
                throw smackException;
            }

            if (config.getSecurityMode() != ConnectionConfiguration.SecurityMode.disabled) 
            {
                sendNonza(new StartTls());
            } 
            else 
            {
                tlsHandled.reportSuccess();
            }
        } 
        else 
        {
            tlsHandled.reportSuccess();
        }

        if (getSASLAuthentication().authenticationSuccessful()) 
        {
            maybeCompressFeaturesReceived.reportSuccess();
        }
    }    
}
