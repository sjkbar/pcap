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
public class ShareInfoStruct implements StructInterface{

	int level;
	ContainerInterface shareInfo;
	ContainerTypeMapper mapper;
	@Override
	public void parse(Buffer b) {
		// TODO Auto-generated method stub
		
	}
	public int getLevel() {
		return level;
	}
	public void setLevel(int level) {
		this.level = level;
	}
	public ContainerInterface getShareInfo() {
		return shareInfo;
	}
	public void setShareInfo(ContainerInterface shareInfo) {
		this.shareInfo = shareInfo;
	}
}
