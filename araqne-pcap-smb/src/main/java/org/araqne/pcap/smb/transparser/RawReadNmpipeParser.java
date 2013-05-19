package org.araqne.pcap.smb.transparser;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.transreq.RawReadNmpipeRequest;
import org.araqne.pcap.smb.transresp.RawReadNmpipeResponse;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class RawReadNmpipeParser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer) {
		RawReadNmpipeRequest transData = new RawReadNmpipeRequest();
		transData.setSubCommand(ByteOrderConverter.swap(setupBuffer.getShort()));
		transData.setFid(ByteOrderConverter.swap(setupBuffer.getShort()));
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer, SmbSession session) {
		RawReadNmpipeResponse transData = new RawReadNmpipeResponse();
		byte []byteRead = new byte[setupBuffer.readableBytes()];
		setupBuffer.gets(byteRead);
		transData.setByteRead(byteRead);
		// TODO Auto-generated method stub
		return null;
	}

}
