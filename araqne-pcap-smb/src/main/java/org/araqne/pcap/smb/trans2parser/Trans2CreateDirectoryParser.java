package org.araqne.pcap.smb.trans2parser;

import org.araqne.pcap.netbios.NetBiosNameCodec;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.trans2req.Trans2CreateDirectoryRequest;
import org.araqne.pcap.smb.trans2resp.Trans2CreateDirectoryResponse;
import org.araqne.pcap.smb.transparser.TransParser;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class Trans2CreateDirectoryParser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer) {
		Trans2CreateDirectoryRequest transData = new Trans2CreateDirectoryRequest();
		transData.setSubcommand(ByteOrderConverter.swap(setupBuffer.getShort()));
		transData.setReserved(ByteOrderConverter.swap(parameterBuffer.getInt()));
		transData.setDirectoryName(NetBiosNameCodec.readSmbUnicodeName(parameterBuffer));
		// TODO read smb fea list
		return transData;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer , SmbSession session) {
		Trans2CreateDirectoryResponse transData = new Trans2CreateDirectoryResponse();
		transData.setEaErrorOffset(ByteOrderConverter.swap(parameterBuffer.getShort()));
		return transData;
	}

}
