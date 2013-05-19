package org.araqne.pcap.smb.trans2struct.setinfostruct;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransStruct;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class SmbSetFileAllocationInfo implements TransStruct{

	long allocationSize;

	public long getAllocationSize() {
		return allocationSize;
	}

	public void setAllocationSize(long allocationSize) {
		this.allocationSize = allocationSize;
	}

	@Override
	public TransStruct parse(Buffer b , SmbSession session) {
		allocationSize = ByteOrderConverter.swap(b.getLong()); 
		return this;
	}
	@Override
	public String toString(){
		return String.format("");
	}
}
