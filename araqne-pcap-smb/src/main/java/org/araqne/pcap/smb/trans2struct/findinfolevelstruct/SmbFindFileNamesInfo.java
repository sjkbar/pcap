package org.araqne.pcap.smb.trans2struct.findinfolevelstruct;

import org.araqne.pcap.netbios.NetBiosNameCodec;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransStruct;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class SmbFindFileNamesInfo implements TransStruct{

	int nextEntryOffset;
	int fileIndex;
	int fileNameLength;
	String fileName;
	public int getNextEntryoffset() {
		return nextEntryOffset;
	}
	public void setNextEntryoffset(int nextEntryoffset) {
		this.nextEntryOffset = nextEntryoffset;
	}
	public int getFileIndex() {
		return fileIndex;
	}
	public void setFileIndex(int fileIndex) {
		this.fileIndex = fileIndex;
	}
	public int getFileNameLength() {
		return fileNameLength;
	}
	public void setFileNameLength(int fileNameLength) {
		this.fileNameLength = fileNameLength;
	}
	public String getFileName() {
		return fileName;
	}
	public void setFileName(String fileName) {
		this.fileName = fileName;
	}
	public TransStruct parse(Buffer b , SmbSession session){
		nextEntryOffset = ByteOrderConverter.swap(b.getInt());
		fileIndex = ByteOrderConverter.swap(b.getInt());
		fileNameLength = ByteOrderConverter.swap(b.getInt());
		fileName = NetBiosNameCodec.readSmbUnicodeName(b, fileNameLength);
		b.reset();
		b.skip(nextEntryOffset);
		return this;
	}
	@Override
	public String toString(){
		return String.format("Third Level Structure : Smb Find File Name info\n" +
				"nextEntryOffset = 0x%s , fileIndex = 0x%s , fileNameLength = 0x%s\n" +
				"fileName = %s\n",
				Integer.toHexString(this.nextEntryOffset) , Integer.toHexString(this.fileIndex) , Integer.toHexString(this.fileNameLength),
				this.fileName);
	}
}
