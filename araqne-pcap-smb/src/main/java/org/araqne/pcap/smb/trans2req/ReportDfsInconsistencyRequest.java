package org.araqne.pcap.smb.trans2req;

import org.araqne.pcap.smb.TransData;

public class ReportDfsInconsistencyRequest implements TransData{
	@Override
	public String toString(){
		return String.format("Trans2 Second Level : Report Dfs Inconsistency Request\n" +
				"there is no implementation");
	}
}
