package org.directtruststandards.timplus.smack.tcp.codec;

import java.util.List;

import org.jivesoftware.smack.packet.Element;
import org.jivesoftware.smack.packet.StreamOpen;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToMessageEncoder;

/**
 * Encodes XMPP element to an XML String representation
 * @author Greg Meyer
 *
 * @since 1.0
 */
public class ElementEncoder extends MessageToMessageEncoder<Element>
{

	@Override
	protected void encode(ChannelHandlerContext ctx, Element element, List<Object> out) throws Exception 
	{
		final CharSequence elementXml = element.toXML(StreamOpen.CLIENT_NAMESPACE);
		
		out.add(elementXml.toString());
	}

}
