/**
 * 
 */
package org.araqne.pcap.dcerpc.srvsvc.structure.containers;

import java.util.ArrayList;

import org.araqne.pcap.dcerpc.srvsvc.structure.containers.infos.ShareInfo1;
import org.araqne.pcap.util.Buffer;

/**
 * @author tgnice@nchovy.com
 *
 */
public class ShareInfo1Container  implements ContainerInterface{

	int entriesRead;
	ArrayList<ShareInfo1> buffer;
	@Override
	public void parse(Buffer b) {
		// TODO Auto-generated method stub
		
	}

}
