package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.QueryInfoDiskRequest;
import org.araqne.pcap.smb.response.QueryInfoDiskResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;
//0x80
public class QueryInfoDiskParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		QueryInfoDiskRequest data = new QueryInfoDiskRequest();
		data.setWordCount(b.get());
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		QueryInfoDiskResponse data = new QueryInfoDiskResponse();
		data.setWordCount(b.get());
		data.setTotalUnits(ByteOrderConverter.swap(b.getShort()));
		data.setBlocksPerUnit(ByteOrderConverter.swap(b.getShort()));
		data.setBlockSize(ByteOrderConverter.swap(b.getShort()));
		data.setFreeUnits(ByteOrderConverter.swap(b.getShort()));
		data.setReserved(ByteOrderConverter.swap(b.getShort()));
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
}
