package org.araqne.pcap.smb.comparser;

import org.araqne.pcap.netbios.NetBiosNameCodec;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.FindCloseRequest;
import org.araqne.pcap.smb.response.FindCloseResponse;
import org.araqne.pcap.smb.rr.FileAttributes;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.smb.structure.SmbResumeKey;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;
//0x84
public class FindCloseParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		FindCloseRequest data = new FindCloseRequest();
		SmbResumeKey []key;
		byte []serverState = new byte[16];
		byte []clientState = new byte[4];
		data.setWordCount(b.get());
		data.setMaxCount(ByteOrderConverter.swap(b.getShort()));
		data.setSearchAttribytes(FileAttributes.parse(ByteOrderConverter.swap(b.getShort())&0xffff));
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		if(b.readableBytes() != data.getByteCount()){
			data.setMalformed(true);
			return data;
		}
		data.setBufferFormat1(b.get());
		data.setFileName(NetBiosNameCodec.readSmbUnicodeName(b));
		data.setBufferFormat2(b.get());
		data.setResumeKeyLength(ByteOrderConverter.swap(b.getShort()));
		key = new SmbResumeKey[data.getResumeKeyLength()/21];
		for(int i =0; i<data.getResumeKeyLength()/21;i++){
			key[i] = new SmbResumeKey();
			key[i].setReserved(b.get());
			b.gets(serverState);
			key[i].setServerState(serverState);
			b.gets(clientState);
			key[i].setClientState(clientState);
		}
		data.setResumeKey(key);
		return data;
	}
	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		FindCloseResponse data = new FindCloseResponse();
		data.setWordCount(b.get());
		data.setCount(ByteOrderConverter.swap(b.getShort()));
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		if(b.readableBytes() != data.getByteCount()){
			data.setMalformed(true);
			return data;
		}
		data.setBufferFormat(b.get());
		data.setDataLength(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
}
