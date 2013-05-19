/*
 * Copyright 2011 Future Systems
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.araqne.pcap.dcerpc.rpce;

import org.araqne.pcap.dcerpc.rpce.packet.UdpPDUInterface;
import org.araqne.pcap.dcerpc.rpce.packet.UdpAckPDU;
import org.araqne.pcap.dcerpc.rpce.packet.UdpCancelAckPDU;
import org.araqne.pcap.dcerpc.rpce.packet.UdpCancelPDU;
import org.araqne.pcap.dcerpc.rpce.packet.UdpFackPDU;
import org.araqne.pcap.dcerpc.rpce.packet.UdpFaultPDU;
import org.araqne.pcap.dcerpc.rpce.packet.UdpNoCallPDU;
import org.araqne.pcap.dcerpc.rpce.packet.UdpPingPDU;
import org.araqne.pcap.dcerpc.rpce.packet.UdpRejectPDU;
import org.araqne.pcap.dcerpc.rpce.packet.UdpRequest;
import org.araqne.pcap.dcerpc.rpce.packet.UdpResponse;
import org.araqne.pcap.dcerpc.rpce.packet.UdpWorkingPDU;
import org.araqne.pcap.dcerpc.rpce.rr.UdpPDUType;

public class UdpPacketTypeMapper {

	public UdpPDUInterface getPDU(UdpPDUType type){
			switch(type){
			case REQUEST :
				return new UdpRequest();
			case PING :
				return new UdpPingPDU();
			case RESPONSE :
				return new UdpResponse();
			case FAULT :
				return new UdpFaultPDU();
			case WORKING :
				return new UdpWorkingPDU();
			case NOCALL :
				return new UdpNoCallPDU();
			case REJECT :
				return new UdpRejectPDU();
			case ACK :
				return new UdpAckPDU();
			case CL_CANCEL :
				return new UdpCancelPDU();
			case FACK :
				return new UdpFackPDU();
			case CANCEL_ACK :
				return new UdpCancelAckPDU();
			default :
				new IllegalAccessException("UdpPacket Mapper : invalid Packet Type + " + type);
				return null;
		}
	}
}
