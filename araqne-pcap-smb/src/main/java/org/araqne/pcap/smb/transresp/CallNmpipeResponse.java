package org.araqne.pcap.smb.transresp;

import org.araqne.pcap.smb.TransData;

public class CallNmpipeResponse implements TransData{
	
	byte []readData;

	public byte[] getReadData() {
		return readData;
	}

	public void setReadData(byte[] readData) {
		this.readData = readData;
	}
	@Override
	public String toString(){
		return String.format("");
	}
}
