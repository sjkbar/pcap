package org.araqne.pcap.smb.transresp;

import org.araqne.pcap.smb.TransData;

public class RawWriteNmpipeResponse implements TransData{
	short bytesWritten;

	public short getBytesWritten() {
		return bytesWritten;
	}

	public void setBytesWritten(short bytesWritten) {
		this.bytesWritten = bytesWritten;
	}
	@Override
	public String toString(){
		return String.format("");
	}
}
