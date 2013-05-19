package org.araqne.pcap.smb.ntparser;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.ntreq.NtIoctlRequest;
import org.araqne.pcap.smb.ntresp.NtIoctlResponse;
import org.araqne.pcap.smb.transparser.TransParser;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class NtIoctlParser implements TransParser{
	private final static int FSCTL_SRV_ENUMERATE_SNAPSHOTS = 0x00144064;
	private final static int FSCTL_SRV_REQUEST_RESUME_KEY = 0x00140078;
	private final static int FSCTL_SRV_COPYCHUNK = 0x001440f2;
	
	@Override
	public TransData parseRequest(Buffer setupBuffer , Buffer parameterBuffer,  Buffer dataBuffer) {
		NtIoctlRequest transData = new NtIoctlRequest();
		// setupBuffer parse start 
		transData.setFucntionCode(ByteOrderConverter.swap(setupBuffer.getInt()));
		transData.setFid(ByteOrderConverter.swap(setupBuffer.getShort()));
		transData.setIsFctl(setupBuffer.get());
		transData.setIsFlags(setupBuffer.get());
		// setupBuffer parser end
		if(transData.getFucntionCode() == FSCTL_SRV_ENUMERATE_SNAPSHOTS)
		{
			// no action there is no NttransParameters and TransData
		}
		else if(transData.getFucntionCode() == FSCTL_SRV_REQUEST_RESUME_KEY)
		{
			
		}
		else if(transData.getFucntionCode() == FSCTL_SRV_COPYCHUNK)
		{
			
		}
		else
		{
			new IllegalAccessException("unavailable NtTransact Ioctl subcommand");
		}
		
		return transData;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer , Buffer parameterBuffer,  Buffer dataBuffer , SmbSession session) {
		NtIoctlResponse transData = new NtIoctlResponse();
		//start setupBuffer parse
		transData.setFunctionCode(ByteOrderConverter.swap(setupBuffer.getShort()));
		//end of setupBuffer
		// there is no parameterBuffer use
		
		if(setupBuffer.readableBytes() != 0)
		{
			byte []NtTransData = new byte[setupBuffer.readableBytes()];
			dataBuffer.gets(NtTransData);
			transData.setData(NtTransData);
		}
		return transData;
	}

}
