package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.TreeDisconnectRequest;
import org.araqne.pcap.smb.response.TreeDisconnectResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;
//0x71
public class TreeDisconnectParser implements SmbDataParser{
	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		TreeDisconnectRequest data = new TreeDisconnectRequest();
		data.setWordCount(b.get());
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return null;
	}
	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		TreeDisconnectResponse data = new TreeDisconnectResponse();
		data.setWordCount(b.get());
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return null;
	}
}
