package org.araqne.pcap.smb.trans2struct.setinfostruct;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransStruct;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class SmbSetFileEndOfFileInfo implements TransStruct {
	long endOfFile;

	public long getEndOfFile() {
		return endOfFile;
	}

	public void setEndOfFile(long endOfFile) {
		this.endOfFile = endOfFile;
	}

	@Override
	public TransStruct parse(Buffer b , SmbSession session) {
		endOfFile = ByteOrderConverter.swap(b.getLong());
		return this;
	}
	@Override
	public String toString(){
		return String.format("");
	}
}
