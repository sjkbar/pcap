package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.FindClose2Request;
import org.araqne.pcap.smb.response.FindClose2Response;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;
//0x34
public class FindClose2Parser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		FindClose2Request data = new FindClose2Request();
		data.setWordCount(b.get());
		data.setSearchHandle(ByteOrderConverter.swap(b.getShort()));
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		FindClose2Response data = new FindClose2Response();
		data.setWordCount(b.get());
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
}
