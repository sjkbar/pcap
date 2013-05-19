package org.araqne.pcap.smb.trans2struct.queryinfostruct;

import org.araqne.pcap.netbios.NetBiosNameCodec;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransStruct;
import org.araqne.pcap.smb.rr.ExtFileAttributes;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class SmbQueryFileAllInfo implements TransStruct{

	long creationTime;
	long lastAccessTime;
	long lastWriteTime;
	long lastChangeTime;
	ExtFileAttributes extFileAttributes;
	int resrved1;
	long allocationSize;
	long endOfFile;
	int numberOfLinks;
	byte deletePending;
	byte directory;
	short reserved2;
	int eaSize;
	int fileNameLength;
	String fileName;
	@Override
	public TransStruct parse(Buffer b , SmbSession session) {
		creationTime = ByteOrderConverter.swap(b.getLong());
		lastAccessTime = ByteOrderConverter.swap(b.getLong());
		lastWriteTime = ByteOrderConverter.swap(b.getLong());
		lastChangeTime = ByteOrderConverter.swap(b.getLong());
		extFileAttributes = ExtFileAttributes.parse(ByteOrderConverter.swap(b.getInt()));
		resrved1 = ByteOrderConverter.swap(b.getInt());
		allocationSize = ByteOrderConverter.swap(b.getLong());
		endOfFile = ByteOrderConverter.swap(b.getLong());
		numberOfLinks = ByteOrderConverter.swap(b.getInt());
		deletePending = b.get();
		directory = b.get();
		reserved2 = ByteOrderConverter.swap(b.getShort());
		eaSize = ByteOrderConverter.swap(b.getInt());
		fileNameLength = ByteOrderConverter.swap(b.getInt());
		fileName = NetBiosNameCodec.readSmbUnicodeName(b, fileNameLength);
		return this;
	}
	@Override
	public String toString(){
		return String.format("");
	}
}
