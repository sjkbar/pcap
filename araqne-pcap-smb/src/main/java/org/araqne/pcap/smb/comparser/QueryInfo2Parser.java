package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.QueryInfo2Request;
import org.araqne.pcap.smb.response.QueryInfo2Response;
import org.araqne.pcap.smb.rr.FileAttributes;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;
//0x23
public class QueryInfo2Parser implements SmbDataParser{
	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		QueryInfo2Request data = new QueryInfo2Request();
		data.setWordCount(b.get());
		data.setFid(ByteOrderConverter.swap(b.getShort()));
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		QueryInfo2Response data = new QueryInfo2Response();
		data.setWordCount(b.get());
		data.setCreateDate(ByteOrderConverter.swap(b.getShort()));
		data.setCreateTime(ByteOrderConverter.swap(b.getShort()));
		data.setLastAccessDate(ByteOrderConverter.swap(b.getShort()));
		data.setLastAccessTime(ByteOrderConverter.swap(b.getShort()));
		data.setLastWriteDate(ByteOrderConverter.swap(b.getShort()));
		data.setLastWriteTime(ByteOrderConverter.swap(b.getShort()));
		data.setFileDateSize(b.getInt());
		data.setFileAllocationSize(b.getInt());
		data.setFileAttributes(FileAttributes.parse(b.get() & 0xff));
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
}
