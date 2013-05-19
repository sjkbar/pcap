/*
 * Copyright 2011 Future Systems, Inc
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
package org.araqne.pcap.netbios;

import java.nio.ByteBuffer;

import org.araqne.pcap.Injectable;
import org.araqne.pcap.netbios.rr.DatagramHeader;
import org.araqne.pcap.decoder.udp.UdpPacket;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ChainBuffer;

public class NetBiosDatagramPacket implements Injectable {
	private UdpPacket udpPacket;
	private DatagramHeader header;
	private DatagramData data;

	public NetBiosDatagramPacket(DatagramHeader header, DatagramData data) {
		this.header = header;
		this.data = data;
	}

	public UdpPacket getUdpPacket() {
		return udpPacket;
	}

	public void setUdpPacket(UdpPacket udpPacket) {
		this.udpPacket = udpPacket;
	}

	public DatagramHeader getHeader() {
		return header;
	}

	public DatagramData getData() {
		return data;
	}

	@Override
	public Buffer getBuffer() {
		ByteBuffer headerb = ByteBuffer.allocate(10);
		Buffer buffer = new ChainBuffer();
		/*
		protected NetBiosDatagramType msgType;
		protected byte flags;
		protected short dgmID;
		protected InetAddress addresses;
		protected short port;*/  //this section is  common field
		buffer.addLast(headerb.array());
		return buffer;
	}

	@Override
	public String toString() {
		return header.toString() + data.toString();
	}
}
