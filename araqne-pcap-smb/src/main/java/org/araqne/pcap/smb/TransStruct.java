package org.araqne.pcap.smb;

import org.araqne.pcap.util.Buffer;

public interface TransStruct {

	public TransStruct parse(Buffer b , SmbSession session);
	public String toString();
}
