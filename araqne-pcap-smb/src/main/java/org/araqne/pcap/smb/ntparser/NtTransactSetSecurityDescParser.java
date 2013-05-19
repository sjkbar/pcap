package org.araqne.pcap.smb.ntparser;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.ntreq.NtTransactSetSecurityDescRequest;
import org.araqne.pcap.smb.ntresp.NtTransactSetSecurityDescResponse;
import org.araqne.pcap.smb.transparser.TransParser;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class NtTransactSetSecurityDescParser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer , Buffer parameterBuffer,  Buffer dataBuffer) {
		NtTransactSetSecurityDescRequest transData = new NtTransactSetSecurityDescRequest();
		//there is no use setupBuffer
		//start parameterBuffer
		transData.setFid(ByteOrderConverter.swap(parameterBuffer.getShort()));
		transData.setReserved(ByteOrderConverter.swap(parameterBuffer.getShort()));
		transData.setSecurityinformation(ByteOrderConverter.swap(parameterBuffer.getInt()));
		//end of parameterBuffer
		//start DataBuffer
		byte []securityDescriptor = new byte[parameterBuffer.readableBytes()];
		parameterBuffer.gets(securityDescriptor);
		transData.setSecurityDescriptor(securityDescriptor);
		// end of dataBuffer
		return transData;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer , Buffer parameterBuffer,  Buffer dataBuffer , SmbSession session) {
		NtTransactSetSecurityDescResponse transData = new NtTransactSetSecurityDescResponse();
		// do not response
		return transData;
	}

}
