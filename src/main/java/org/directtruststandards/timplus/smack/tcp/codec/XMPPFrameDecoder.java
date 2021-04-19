package org.directtruststandards.timplus.smack.tcp.codec;

import java.nio.charset.Charset;
import java.util.List;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.CompositeByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.codec.CorruptedFrameException;
import io.netty.handler.codec.TooLongFrameException;

/**
 * Reimplementation of the XML Frame Decoder that allows XMPP stream fragments to 
 * broken in to individual stanzas.  The result in an XMPP stanza the is preceded
 * by the opening stream to preserve the namespace.  This allows fragments to be 
 * parsed by an XML Pull parser.
 * 
 * @author Greg Meyer
 * @since 1.0
 */
public class XMPPFrameDecoder extends ByteToMessageDecoder
{

	protected static final String OPEN_STREAM = "<stream:stream xmlns:stream=\"http://etherx.jabber.org/streams\" xmlns=\"jabber:client\"  xml:lang=\"en\">";
	
    private final int maxFrameLength;

    public XMPPFrameDecoder(int maxFrameLength) 
    {
        if (maxFrameLength < 1) 
        {
            throw new IllegalArgumentException("maxFrameLength must be a positive int");
        }
        this.maxFrameLength = maxFrameLength;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) throws Exception 
    {
        boolean openingBracketFound = false;
        boolean atLeastOneXmlElementFound = false;
        boolean inCDATASection = false;
        boolean inStartStreamBlock = false;
        boolean prependOpenStream = true;
        
        long openBracketsCount = 0;
        int length = 0;
        int leadingWhiteSpaceCount = 0;
        final int bufferLength = in.writerIndex();

        if (bufferLength > maxFrameLength) {
            // bufferLength exceeded maxFrameLength; dropping frame
            in.skipBytes(in.readableBytes());
            fail(bufferLength);
            return;
        }

        for (int i = in.readerIndex(); i < bufferLength; i++) 
        {
            final byte readByte = in.getByte(i);
            if (!openingBracketFound && Character.isWhitespace(readByte)) 
            {
                // xml has not started and whitespace char found
                leadingWhiteSpaceCount++;
            } 
            else if (!openingBracketFound && readByte != '<') 
            {
                // garbage found before xml start
                fail(ctx);
                in.skipBytes(in.readableBytes());
                return;
            } 
            else if (!inCDATASection && readByte == '<') 
            {
                openingBracketFound = true;

                if (isStreamBlockStart(in, i))
                {
                	inStartStreamBlock = true;
                	prependOpenStream = false;
                }
                
                if (i < bufferLength - 1) 
                {
                    final byte peekAheadByte = in.getByte(i + 1);
                    if (peekAheadByte == '/') 
                    {
                        // found </, we must check if it is enclosed
                        int peekFurtherAheadIndex = i + 2;
                        while (peekFurtherAheadIndex <= bufferLength - 1) 
                        {
                            //if we have </ and enclosing > we can decrement openBracketsCount
                            if (in.getByte(peekFurtherAheadIndex) == '>') 
                            {
                                openBracketsCount--;
                                break;
                            }
                            peekFurtherAheadIndex++;
                        }
                    } 
                    else if (isValidStartCharForXmlElement(peekAheadByte)) 
                    {
                        atLeastOneXmlElementFound = true;
                        // char after < is a valid xml element start char,
                        // incrementing openBracketsCount
                        openBracketsCount++;
                    } 
                    else if (peekAheadByte == '!') 
                    {
                        if (isCommentBlockStart(in, i)) 
                        {
                            // <!-- comment --> start found
                            openBracketsCount++;
                        } 
                        else if (isCDATABlockStart(in, i)) 
                        {
                            // <![CDATA[ start found
                            openBracketsCount++;
                            inCDATASection = true;
                        }
                    } 
                    else if (peekAheadByte == '?') 
                    {
                        // <?xml ?> start found
                        openBracketsCount++;
                    }
                }
            } 
            else if (!inCDATASection && !inStartStreamBlock && readByte == '/') 
            {
                if (i < bufferLength - 1 && in.getByte(i + 1) == '>') 
                {
                    // found />, decrementing openBracketsCount
                    openBracketsCount--;
                }
            } 
            else if (readByte == '>') 
            {
                length = i + 1;

                if (i - 1 > -1) 
                {
                    final byte peekBehindByte = in.getByte(i - 1);

                    if (inStartStreamBlock)
                    {
                    	openBracketsCount--;
                    	if (openBracketsCount == 0)
                    	{
                    		inStartStreamBlock = false;
                    	}
                    }
                    else if (!inCDATASection) 
                    {
                        if (peekBehindByte == '?') 
                        {
                            // an <?xml ?> tag was closed
                            openBracketsCount--;
                        } 
                        else if (peekBehindByte == '-' && i - 2 > -1 && in.getByte(i - 2) == '-') 
                        {
                            // a <!-- comment --> was closed
                            openBracketsCount--;
                        }
                    } 
                    else if (peekBehindByte == ']' && i - 2 > -1 && in.getByte(i - 2) == ']') 
                    {
                        // a <![CDATA[...]]> block was closed
                        openBracketsCount--;
                        inCDATASection = false;
                    }

                }

                if (atLeastOneXmlElementFound && openBracketsCount == 0) 
                {
                    // xml is balanced, bailing out
                    break;
                }
            }
        }

        final int readerIndex = in.readerIndex();
        int xmlElementLength = length - readerIndex;
        
        // Keeping the next couple of lines around for debugging when needed.
        
        //final ByteBuf tempFrame =
        //      extractFrame(in, readerIndex + leadingWhiteSpaceCount, xmlElementLength - leadingWhiteSpaceCount, prependOpenStream);

        //System.out.println(tempFrame.getCharSequence(0, tempFrame.readableBytes(), Charset.defaultCharset()));

        
        if (openBracketsCount == 0 && xmlElementLength > 0) 
        {
            if (readerIndex + xmlElementLength >= bufferLength) 
            {
                xmlElementLength = in.readableBytes();
            }
            final ByteBuf frame =
                    extractFrame(in, readerIndex + leadingWhiteSpaceCount, xmlElementLength - leadingWhiteSpaceCount, prependOpenStream);
            in.skipBytes(xmlElementLength);
            out.add(frame);
        }
    }

    private void fail(long frameLength) {
        if (frameLength > 0) {
            throw new TooLongFrameException(
                            "frame length exceeds " + maxFrameLength + ": " + frameLength + " - discarded");
        } else {
            throw new TooLongFrameException(
                            "frame length exceeds " + maxFrameLength + " - discarding");
        }
    }

    private static void fail(ChannelHandlerContext ctx) {
        ctx.fireExceptionCaught(new CorruptedFrameException("frame contains content before the xml starts"));
    }

    private static ByteBuf extractFrame(ByteBuf buffer, int index, int length, boolean prependOpenStream) 
    {
    	final Charset utf8 = Charset.forName("UTF-8");
    	
    	final CompositeByteBuf compBuf = Unpooled.compositeBuffer(prependOpenStream ? 1 : 2);
    	final ByteBuf openBuf =  Unpooled.buffer((prependOpenStream) ? OPEN_STREAM.length() : 0);
    	if (prependOpenStream)
    	{
    		openBuf.writeCharSequence(OPEN_STREAM, utf8);
    		compBuf.addComponent(openBuf);
    	}
    	
    	ByteBuf contentBuf = buffer.copy(index, length);
    	
    	compBuf.addComponent(contentBuf);
    	
    	compBuf.writerIndex(openBuf.writerIndex() + contentBuf.writerIndex());
    	
        return compBuf;
        
    	
    }

    /**
     * Asks whether the given byte is a valid
     * start char for an xml element name.
     * <p/>
     * Please refer to the
     * <a href="https://www.w3.org/TR/2004/REC-xml11-20040204/#NT-NameStartChar">NameStartChar</a>
     * formal definition in the W3C XML spec for further info.
     *
     * @param b the input char
     * @return true if the char is a valid start char
     */
    private static boolean isValidStartCharForXmlElement(final byte b) {
        return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b == ':' || b == '_';
    }

    private static boolean isCommentBlockStart(final ByteBuf in, final int i) {
        return i < in.writerIndex() - 3
                && in.getByte(i + 2) == '-'
                && in.getByte(i + 3) == '-';
    }

    private static boolean isCDATABlockStart(final ByteBuf in, final int i) {
        return i < in.writerIndex() - 8
                && in.getByte(i + 2) == '['
                && in.getByte(i + 3) == 'C'
                && in.getByte(i + 4) == 'D'
                && in.getByte(i + 5) == 'A'
                && in.getByte(i + 6) == 'T'
                && in.getByte(i + 7) == 'A'
                && in.getByte(i + 8) == '[';
    }

    private static boolean isStreamBlockStart(final ByteBuf in, final int i) 
    {
    	
          return   ((in.getByte(i + 0) == '<'
        		&&  in.getByte(i + 1) == 's'
                && in.getByte(i + 2) == 't'
                && in.getByte(i + 3) == 'r'
                && in.getByte(i + 4) == 'e'
                && in.getByte(i + 5) == 'a'
                && in.getByte(i + 6) == 'm'
                && in.getByte(i + 7) == ' ') ||
        		  
        		  (in.getByte(i + 0) == '<'
          		  && in.getByte(i + 1) == 's'
                  && in.getByte(i + 2) == 't'
                  && in.getByte(i + 3) == 'r'
                  && in.getByte(i + 4) == 'e'
                  && in.getByte(i + 5) == 'a'
                  && in.getByte(i + 6) == 'm'
                  && in.getByte(i + 7) == ':')
          		  && in.getByte(i + 8) == 's'
                  && in.getByte(i + 9) == 't'
                  && in.getByte(i + 10) == 'r'
                  && in.getByte(i + 11) == 'e'
                  && in.getByte(i + 12) == 'a'
                  && in.getByte(i + 13) == 'm')  ;

    }
}
