package org.araqne.pcap.smb;

import org.araqne.pcap.util.Buffer;


public interface SmbProcessor {
/*	public void process();
	public void 
*/
	public void processTcpRx(Buffer b);
	public void processTcpTx(Buffer b);
	public void processUdp(Buffer b);
	public void processMailslot(Buffer b);
}
