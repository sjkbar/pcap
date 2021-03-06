/*
 * Copyright 2010 NCHOVY

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
package org.araqne.pcap.pop;

import java.io.InputStream;
import java.util.Date;
import java.util.Set;

import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

/**
 * @author mindori
 */
public interface Pop3Data {
	int getSize();

	Date getSentDate();

	Set<InternetAddress> getFrom();
	
	Set<InternetAddress> getTo();
	
	Set<InternetAddress> getCc();
	
	String getSubject();
	
	String getContentType();
	
	String getTextContent();
	
	String getHtmlContent();
	
	Set<String> getAttachmentNames();
	
	InputStream getAttachment(String fileName);

	MimeMessage getMimeMessage();
}
