package org.araqne.pcap.smb.trans2parser;

import org.araqne.pcap.netbios.NetBiosNameCodec;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.trans2req.SetPathInformationRequest;
import org.araqne.pcap.smb.trans2resp.SetPathInformationResponse;
import org.araqne.pcap.smb.transparser.TransParser;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class SetPathInformationParser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer) {
		SetPathInformationRequest transData = new SetPathInformationRequest();
		transData.setSubcommand(ByteOrderConverter.swap(setupBuffer.getShort()));
		transData.setInformationLevel(ByteOrderConverter.swap(parameterBuffer.getShort()));
		transData.setReserved(ByteOrderConverter.swap(parameterBuffer.getInt()));
		transData.setFileName(NetBiosNameCodec.readSmbUnicodeName(parameterBuffer));
		//read Data
		//follow Informationlevel
		return transData;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer , SmbSession session) {
		SetPathInformationResponse transData = new SetPathInformationResponse();
		transData.setEaErrorOffset(ByteOrderConverter.swap(parameterBuffer.getShort()));
		return transData;
	}

}
