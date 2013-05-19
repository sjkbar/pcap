package org.araqne.pcap.smb.trans2parser;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.trans2req.SetFileInformationRequest;
import org.araqne.pcap.smb.trans2resp.SetFileInformationResponse;
import org.araqne.pcap.smb.transparser.TransParser;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class SetFileInformationParser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer  , Buffer parameterBuffer , Buffer dataBuffer) {
		SetFileInformationRequest transData = new SetFileInformationRequest();
		transData.setSubcommand(ByteOrderConverter.swap(setupBuffer.getShort()));
		transData.setFid(ByteOrderConverter.swap(parameterBuffer.getShort()));
		transData.setInformaiotnLevel(ByteOrderConverter.swap(parameterBuffer.getShort()));
		transData.setReserved(ByteOrderConverter.swap(parameterBuffer.getShort()));
		//TODO : dataBuffer parsing depend on information level
		return transData;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer  , Buffer parameterBuffer , Buffer dataBuffer, SmbSession session) {
		SetFileInformationResponse transData = new SetFileInformationResponse();
		transData.setEaErrorOffset(ByteOrderConverter.swap(parameterBuffer.getShort()));
		return transData;
	}

}
