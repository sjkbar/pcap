package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.netbios.NetBiosNameCodec;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.SearchRequest;
import org.araqne.pcap.smb.response.SearchResponse;
import org.araqne.pcap.smb.rr.FileAttributes;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbDirectoryInfo;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.smb.structure.SmbResumeKey;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;
//0x81
public class SearchParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		SearchRequest data = new SearchRequest();
		SmbResumeKey []keys;
		byte []serverState = new byte[16];
		byte []clientState = new byte[4];
		data.setWordCount(b.get());
		data.setMaxCount(ByteOrderConverter.swap(b.getShort()));
		data.setSearchAttribytes(FileAttributes.parse(ByteOrderConverter.swap(b.getShort()) & 0xff));
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		if(b.readableBytes() != data.getByteCount()){
			data.setMalformed(true);
			return data;
		}
		data.setBufferFormat1(b.get());
		data.setFileName(NetBiosNameCodec.readSmbUnicodeName(b));
		//System.out.println("FileName = " + data.getFileName());
		data.setBufferFormat2(b.get());
		data.setResumeKeyLength(ByteOrderConverter.swap(b.getShort()));
		keys = new SmbResumeKey[data.getResumeKeyLength()/21];
		for(int i=0; i< data.getResumeKeyLength()/21;i++){
			keys[i] = new SmbResumeKey();
			keys[i].setReserved(b.get());
			b.gets(serverState);
			keys[i].setServerState(serverState);
			b.gets(clientState);
			keys[i].setClientState(clientState);
		}
		data.setResumeKey(keys);
		return data;
	}
	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		SearchResponse data = new SearchResponse();
		SmbDirectoryInfo []info;
		SmbResumeKey []key;
		byte []serverState = new byte[16];
		byte []clientState = new byte[4];
		//byte []name = new byte[13];
		data.setWordCount(b.get());
		if(data.getWordCount() != 0){
			data.setCount(ByteOrderConverter.swap(b.getShort()));
		}
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		if(data.getByteCount() ==0 ){
			return data;
		}
		if(b.readableBytes() != data.getByteCount()){
			data.setMalformed(true);
			return data;
		}
		data.setBufferFormat(b.get());
		data.setDataLength(ByteOrderConverter.swap(b.getShort()));
		info = new SmbDirectoryInfo[data.getDataLength()/43];
		key = new SmbResumeKey[data.getDataLength()/43];
		for(int i=0;i<data.getDataLength()/43 ; i++){
			info[i] = new SmbDirectoryInfo();
			 key[i] = new SmbResumeKey();
			//resume key
			key[i].setReserved(b.get());
			b.gets(serverState);
			key[i].setServerState(serverState);
			b.gets(clientState);
			key[i].setClientState(clientState);
			//set directory info
			info[i].setResumeKey(key[i]);
			info[i].setFileAttributes(FileAttributes.parse(b.get() & 0xff));
			info[i].setLastWriteTime(ByteOrderConverter.swap(b.getShort()));
			info[i].setLastWriteDate(ByteOrderConverter.swap(b.getShort()));
			info[i].setFileSize(ByteOrderConverter.swap(b.getInt()));
			info[i].setFilename(NetBiosNameCodec.readOemName(b, 13));
		}
		data.setDirectoryInformationData(info);
		return data;
	}
}
