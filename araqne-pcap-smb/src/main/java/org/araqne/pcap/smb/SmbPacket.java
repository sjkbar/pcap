package org.araqne.pcap.smb;

import org.araqne.pcap.Injectable;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;

public class SmbPacket implements Injectable {
	public SmbHeader header;
	public SmbData data;

	public String toString() {
		return header.toString() + data.toString();
	}

	@Override
	public Buffer getBuffer() {
		// TODO Auto-generated method stub
		return null;
	}
}
