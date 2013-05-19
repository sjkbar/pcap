/**
 * 
 */
package org.araqne.pcap.dcerpc.srvsvc.structure.containers;

import java.util.ArrayList;

import org.araqne.pcap.dcerpc.srvsvc.structure.containers.infos.FileInfo2;
import org.araqne.pcap.util.Buffer;

/**
 * @author tgnice@nchovy.com
 *
 */
public class FileInfo2Container implements ContainerInterface{

	int EntriesRead;
	ArrayList<FileInfo2> buffer;
	@Override
	public void parse(Buffer b) {
		// TODO Auto-generated method stub
		
	}
	public int getEntriesRead() {
		return EntriesRead;
	}
	public void setEntriesRead(int entriesRead) {
		EntriesRead = entriesRead;
	}
	public ArrayList<FileInfo2> getBuffer() {
		return buffer;
	}
	public void setBuffer(ArrayList<FileInfo2> buffer) {
		this.buffer = buffer;
	}
	
}
