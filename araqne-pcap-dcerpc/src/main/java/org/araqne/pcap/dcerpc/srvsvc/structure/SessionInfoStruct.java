/**
 * 
 */
package org.araqne.pcap.dcerpc.srvsvc.structure;

import org.araqne.pcap.dcerpc.srvsvc.ContainerTypeMapper;
import org.araqne.pcap.dcerpc.srvsvc.structure.containers.ContainerInterface;
import org.araqne.pcap.util.Buffer;

/**
 * @author tgnice@nchovy.com
 *
 */
public class SessionInfoStruct implements StructInterface{

	int level;
	ContainerInterface sessionInfo;
	ContainerTypeMapper mapper;
	public int getLevel() {
		return level;
	}
	public void setLevel(int level) {
		this.level = level;
	}
	public ContainerInterface getSessionInfo() {
		return sessionInfo;
	}
	public void setSessionInfo(ContainerInterface sessionInfo) {
		this.sessionInfo = sessionInfo;
	}
	@Override
	public void parse(Buffer b) {
		// TODO Auto-generated method stub
		
	}
	
}
