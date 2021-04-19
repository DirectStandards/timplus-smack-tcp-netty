package org.directtruststandards.timplus.smack.tcp;


import org.jivesoftware.smack.SmackException.ConnectionException;
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;


public class XMPPNettyTCPConnection_connectTest 
{
	@Test
	public void testTCPConnection_providedHosts_assertConnected() throws Exception
	{
		try
		{
			final XMPPTCPConnectionConfiguration config = XMPPTCPConnectionConfiguration.builder()
					.setHost("securehealthemail.com")
					.setPort(5222)
					.setXmppDomain("direct.securehealthemail.com")
					.setCompressionEnabled(true)
					.build();
			
			final XMPPNettyTCPConnection con = new XMPPNettyTCPConnection(config);
			con.connect();
		}
		catch (Exception e)
		{
			
		}
	}
	
	@Test
	public void testTCPConnection_providedHosts_invalidTarget_assertException() throws Exception
	{
		final XMPPTCPConnectionConfiguration config = XMPPTCPConnectionConfiguration.builder()
				.setHost("bogusserver.com")
				.setPort(5222)
				.setXmppDomain("bogusserver.com")
				.build();
		
		Assertions.assertThrows(ConnectionException.class, () -> 
		{
			final XMPPNettyTCPConnection con = new XMPPNettyTCPConnection(config);
			con.connect();
		});

		
	}
}
