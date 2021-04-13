package org.directtruststandards.timplus.smack.tcp;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.jivesoftware.smack.ConnectionConfiguration;
import org.junit.jupiter.api.Test;

public class XMPPNettyTCPConnection_constructTest 
{
	@Test
	public void testConstructConnection_construtWithUserPass_assertConfig() throws Exception
	{
		final XMPPNettyTCPConnection con = new XMPPNettyTCPConnection("user@domain.com", "pass");
		
		final ConnectionConfiguration config = con.getConfiguration();
		
		assertEquals("user", config.getUsername());
	}
}
