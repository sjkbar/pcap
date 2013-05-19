package org.araqne.pcap.smb.trans2struct.queryinfostruct;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransStruct;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class SmbQueryFileEaInfo implements TransStruct{

	int eaSize;

	public int getEaSize() {
		return eaSize;
	}

	public void setEaSize(int eaSize) {
		this.eaSize = eaSize;
	}

	@Override
	public TransStruct parse(Buffer b , SmbSession session) {
		eaSize = ByteOrderConverter.swap(b.getInt());
		return this;
	}
	@Override
	public String toString(){
		return String.format("");
	}
}
