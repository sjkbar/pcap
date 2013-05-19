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
public class ConnectInfoStruct implements StructInterface {

	int level;
	ContainerInterface connectionInfo;
	ContainerTypeMapper mapper;
	@Override
	public void parse(Buffer b) {
		// TODO Auto-generated method stub
		
	}
	

}
