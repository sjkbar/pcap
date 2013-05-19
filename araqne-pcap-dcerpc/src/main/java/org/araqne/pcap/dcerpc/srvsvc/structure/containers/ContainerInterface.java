/**
 * 
 */
package org.araqne.pcap.dcerpc.srvsvc.structure.containers;

import org.araqne.pcap.util.Buffer;

/**
 * @author tgnice@nchovy.com
 *
 */
public interface ContainerInterface {

	int EntriesRead = 0;
	public void parse(Buffer b );
}
