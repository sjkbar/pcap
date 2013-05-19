/**
 * 
 */
package org.araqne.pcap.dcerpc.srvsvc.structure.containers;

import java.util.ArrayList;

import org.araqne.pcap.dcerpc.srvsvc.structure.containers.infos.ShareInfo503I;
import org.araqne.pcap.util.Buffer;

/**
 * @author tgnice@nchovy.com
 *
 */
public class ShareInfo503Container  implements ContainerInterface{

	int entriesRead;
	ArrayList<ShareInfo503I> buffer;
	@Override
	public void parse(Buffer b) {
		// TODO Auto-generated method stub
		
	}

}
