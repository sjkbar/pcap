package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.EchoRequest;
import org.araqne.pcap.smb.response.EchoResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;
//0x2B
public class EchoParser implements SmbDataParser{


	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		EchoRequest data = new EchoRequest();
		byte []buff;
		data.setWordCount(b.get());
		data.setEchoCount(ByteOrderConverter.swap(b.getShort()));
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		buff = new byte[data.getByteCount()];
		b.gets(buff);
		data.setData(buff);
		return data;
	}
	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		EchoResponse data = new EchoResponse();
		byte []buff;
		data.setWordCount(b.get());
		data.setSequenceNumber(ByteOrderConverter.swap(b.getShort()));
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		if(b.readableBytes() != data.getByteCount()){
			data.setMalformed(true);
			return data;
		}
		buff = new byte[data.getByteCount()];
		b.gets(buff);
		data.setData(buff);
		return data;
	}
}
