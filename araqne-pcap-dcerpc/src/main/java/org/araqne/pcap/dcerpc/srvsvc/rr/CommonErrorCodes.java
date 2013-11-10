/**
 * 
 */
package org.araqne.pcap.dcerpc.srvsvc.rr;

import java.util.HashMap;
import java.util.Map;

/**
 * @author tgnice@nchovy.com
 *
 */
public enum CommonErrorCodes {

	;
	private int code;
	CommonErrorCodes(int code) {
		this.code = code;
	}
	static Map<Integer, CommonErrorCodes> codeMap = new HashMap<Integer, CommonErrorCodes>();
	static{
		for(CommonErrorCodes code : CommonErrorCodes.values()){
			codeMap.put(code.getCode(), code);
		}
	}
	public int getCode(){
		return code;
	}
	public static CommonErrorCodes parse(int code){
		return codeMap.get(code);
	}
}
