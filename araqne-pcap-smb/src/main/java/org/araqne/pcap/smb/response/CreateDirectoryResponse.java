package org.araqne.pcap.smb.response;
import org.araqne.pcap.smb.structure.SmbData;
// command Code 0x00
public class CreateDirectoryResponse implements SmbData{

	boolean malformed = false;
	byte wordCount;
	short byteCount;
	public byte getWordCount() {
		return wordCount;
	}
	public void setWordCount(byte wordCount) {
		this.wordCount = wordCount;
	}
	public short getByteCount() {
		return byteCount;
	}
	public void setByteCount(short byteCount) {
		this.byteCount = byteCount;
	}
	
	@Override
	public boolean isMalformed() {
		// TODO Auto-generated method stub
		return malformed;
	}
	@Override
	public void setMalformed(boolean malformed) {
		this.malformed = malformed;
	}
	@Override
	public String toString(){
		return String.format("First Level : Create Directory Response\n" +
				"isMalformed = %s\n" +
				"wordCount = 0x%s(it must 0x00)\n" +
				"byteCount = 0x%s(it must 0x00)\n",
				this.malformed,
				Integer.toHexString(this.wordCount),
				Integer.toHexString(this.byteCount));
	}
}
