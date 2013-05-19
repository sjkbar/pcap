package org.araqne.pcap.smb.comparser;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.SetInfo2Request;
import org.araqne.pcap.smb.response.SetInfo2Response;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

//0x22
public class SetInfo2Parser implements SmbDataParser {
	@Override
	public SmbData parseRequest(SmbHeader h, Buffer b, SmbSession session) {
		SetInfo2Request data = new SetInfo2Request();
		data.setWordCount(b.get());
		data.setFid(ByteOrderConverter.swap(b.getShort()));
		data.setCreateDate(ByteOrderConverter.swap(b.getShort()));
		data.setCreationTime(ByteOrderConverter.swap(b.getShort()));
		data.setLastAccessDate(ByteOrderConverter.swap(b.getShort()));
		data.setLastAccessTime(ByteOrderConverter.swap(b.getShort()));
		data.setLastWriteDate(ByteOrderConverter.swap(b.getShort()));
		data.setLastWriteTime(ByteOrderConverter.swap(b.getShort()));
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}

	@Override
	public SmbData parseResponse(SmbHeader h, Buffer b, SmbSession session) {
		SetInfo2Response data = new SetInfo2Response();
		data.setWordCount(b.get());
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
}
