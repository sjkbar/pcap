/**
 * 
 */
package org.araqne.pcap.dcerpc.srvsvc.structure.containers;

import java.util.ArrayList;

import org.araqne.pcap.dcerpc.srvsvc.structure.containers.infos.SessionInfo0;
import org.araqne.pcap.util.Buffer;

/**
 * @author tgnice@nchovy.com
 *
 */
public class SessionInfo0Container implements ContainerInterface{

	int entriesRead;
	ArrayList<SessionInfo0> buffer;
	@Override
	public void parse(Buffer b) {
		// TODO Auto-generated method stub
		
	}
	public int getEntriesRead() {
		return entriesRead;
	}
	public void setEntriesRead(int entriesRead) {
		this.entriesRead = entriesRead;
	}
	public ArrayList<SessionInfo0> getBuffer() {
		return buffer;
	}
	public void setBuffer(ArrayList<SessionInfo0> buffer) {
		this.buffer = buffer;
	}
}
