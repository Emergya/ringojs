/*
 * ProxyUtils.java Copyright (C) 2013 This file is part of persistenceGeo project
 * 
 * This software is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) any
 * later version.
 * 
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this library; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 * 
 * As a special exception, if you link this library with other files to produce
 * an executable, this library does not by itself cause the resulting executable
 * to be covered by the GNU General Public License. This exception does not
 * however invalidate any other reasons why the executable file might be covered
 * by the GNU General Public License.
 * 
 * Authors:: Alejandro Díaz Torres (mailto:adiaz@emergya.com)
 */
package com.emergya.persistenceGeo.utils;

import it.geosolutions.geoserver.rest.GeoServerRESTPublisher;
import it.geosolutions.geoserver.rest.HTTPUtils;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.StringTokenizer;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.InputStreamRequestEntity;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.PutMethod;
import org.apache.commons.httpclient.params.HttpMethodParams;
import org.apache.commons.io.IOUtils;

/**
 * JsgiServlet extension to do direct proxy
 * 
 * @author <a href="mailto:adiaz@emergya.com">adiaz</a>
 * 
 */
public class ProxyUtils {

	private Map<String, String> authorizedUrls;

	protected String proxyUrl;
	protected int proxyPort;
	protected String proxyUser;
	protected String proxyPassword;
	protected boolean proxyOn;
	protected String[] noProxied;
	protected String[] fullAuthentication;

	/**
	 * Constructor of ProxyPass
	 * 
	 * @param proxyUrl
	 * @param proxyPort
	 * @param proxyUser
	 * @param proxyPassword
	 * @param proxyOn
	 * @param noProxied
	 */
	public ProxyUtils(String proxyUrl, int proxyPort, String proxyUser,
			String proxyPassword, boolean proxyOn, String[] noProxied,
			Map<String, String> authorizedUrls) {
		super();
		this.proxyUrl = proxyUrl;
		this.proxyPort = proxyPort;
		this.proxyUser = proxyUser;
		this.proxyPassword = proxyPassword;
		this.proxyOn = proxyOn;
		this.noProxied = noProxied;
		this.authorizedUrls = authorizedUrls != null ? authorizedUrls
				: new HashMap<String, String>();
	}

	/**
	 * Indica si se debe autorizar cualquier URL o solo los de la lista
	 * authorizedUrls.
	 */
	private static final Boolean MUST_CHECK_URL = Boolean.FALSE;

	/**
	 * The doGet || doPost || doPut method of the servlet. <br>
	 * 
	 * Proxy a request and fill the response.
	 * 
	 * @param request
	 *            the request send by the client to the server
	 * @param response
	 *            the response send by the server to the client
	 * 
	 * @throws IOException
	 * @throws ServletException
	 * @throws FileNotFoundException
	 */
	public void process(HttpServletRequest request, HttpServletResponse response)
			throws FileNotFoundException, ServletException, IOException {
		process(request, response,
				"post".equals(request.getMethod().toLowerCase()));
	}

	/**
	 * The doGet || doPost || doPut method of the servlet. <br>
	 * 
	 * This method is called when a form has its tag value method equals to get.
	 * 
	 * @param request
	 *            the request send by the client to the server
	 * @param response
	 *            the response send by the server to the client
	 * @throws ServletException
	 *             if an error occurred
	 * @throws IOException
	 *             if an error occurred
	 */
	public void process(HttpServletRequest request,
			HttpServletResponse response, boolean post)
			throws ServletException, IOException, FileNotFoundException {

		OutputStream os = response.getOutputStream();

		try {
			// Replaces from authorizedUrls
			String urlParameter = request.getParameter("url");
			if (request.getParameter("url2") != null) {
				urlParameter = request.getParameter("url2");
			}

			String requestURL = manageUrl(urlParameter, request, response);

			// Create and execute method
			HttpClient client = getHttpClient(requestURL);
			HttpMethod method = getMethod(request, response, requestURL);
			
			// copy status
			int status = client.executeMethod(method);
			response.setStatus(status);
			
			// copy headers
			for (Header header: method.getResponseHeaders()){
				response.setHeader(header.getName(), header.getValue());
			}

			// Copy buffer
			InputStream inputStreamProxyResponse = method
					.getResponseBodyAsStream();
			int read = 0;
			byte[] bytes = new byte[1024];
			while ((read = inputStreamProxyResponse.read(bytes)) != -1) {
				os.write(bytes, 0, read);
			}
			inputStreamProxyResponse.close();
			// EoF copy buffer

		} catch (Exception e) {
			// log.error("getInputStream() failed", e);
			// fall through
			e.printStackTrace();
			response.sendError(HttpServletResponse.SC_NOT_FOUND,
					"Page not found.");
		} finally {
			os.flush();
			os.close();
		}
	}

	/**
	 * Process direct put
	 * 
	 * @param url
	 * @param request
	 * @param os
	 * 
	 * @throws IOException
	 */
	protected void put(String url, HttpServletRequest request, OutputStream os)
			throws IOException {
		StringWriter writer = new StringWriter();
		Reader data = request.getReader();
		IOUtils.copy(data, writer);
		String xml = writer.toString();
		//System.out.println("Putting "+ xml);
		if (hasText(xml)) {
			String stringResponse;
			if(request.getContentType().equals(GeoServerRESTPublisher.Format.XML)){
				stringResponse = HTTPUtils.putXml(url, xml, proxyUser,
						proxyPassword);
			}else{
				stringResponse = HTTPUtils.put(url, xml, request.getContentType(), proxyUser,
						proxyPassword);
			}
			os.write(stringResponse.getBytes());
		} else {
			get(url, request, os);
		}
	}

	/**
	 * Process direct post
	 * 
	 * @param url
	 * @param request
	 * @param os
	 * 
	 * @throws IOException
	 */
	protected void post(String url, HttpServletRequest request, OutputStream os)
			throws IOException {
		StringWriter writer = new StringWriter();
		Reader data = request.getReader();
		IOUtils.copy(data, writer);
		String xml = writer.toString();
		//System.out.println("Posting "+ xml);
		if (hasText(xml)) {
			String stringResponse;
			if(request.getContentType().equals(GeoServerRESTPublisher.Format.XML)){
				stringResponse = HTTPUtils.postXml(url, xml, proxyUser,
						proxyPassword);
			}else{
				stringResponse = HTTPUtils.post(url, xml, request.getContentType(), proxyUser,
						proxyPassword);
			}
			os.write(stringResponse.getBytes());
		} else {
			get(url, request, os);
		}
	}

	/**
	 * Process simple get
	 * 
	 * @param url
	 * @param request
	 * @param os
	 * 
	 * @throws IOException
	 */
	protected void get(String url, HttpServletRequest request, OutputStream os)
			throws IOException {
		String stringResponse = HTTPUtils.get(url, proxyUser, proxyPassword);
		os.write(stringResponse.getBytes());
	}

	/**
	 * Obtain a method to mke proxy
	 * 
	 * @param request
	 * @param response
	 * @param requestURL
	 * 
	 * @return HttpMethod
	 * 
	 * @throws Exception
	 */
	protected HttpMethod getMethod(HttpServletRequest request,
			HttpServletResponse response, String requestURL) throws Exception {
		HttpMethod method;
		if (request.getMethod().toLowerCase().equals("get")) {
			method = generateGetMethod(request, response, requestURL);
		} else if (request.getMethod().toLowerCase().equals("post")) {
			method = new PostMethod(requestURL);
			// Solo si es necesario en post
			// ((PostMethod)method).setRequestBody();
			((PostMethod) method)
					.setRequestEntity(new InputStreamRequestEntity(request
							.getInputStream(), request.getContentLength()));
		} else if (request.getMethod().toLowerCase().equals("put")) {
			// put method may not be called
			// method = generateGetMethod(request, response, requestURL);
			method = new PutMethod(requestURL);
			((PutMethod) method).setRequestEntity(new InputStreamRequestEntity(
					request.getInputStream(), request.getContentLength()));
			// ((PutMethod) method).setRequestBody(request.getInputStream());
		} else {
			// unsupported
			// fall through
			response.sendError(HttpServletResponse.SC_NOT_FOUND,
					"Page not found.");
			throw new Exception("Trying to proxy from "
					+ request.getRemoteHost());
		}

		if (isFullAuthentication(requestURL)) {
			method.setDoAuthentication(true);
		}
		HttpMethodParams data = new HttpMethodParams();

		for (Object p : request.getParameterMap().keySet()) {
			if (!"url".equals(p))
				data.setParameter((String) p, request.getParameterMap().get(p));
		}

		method.setParams(data);
		return method;
	}

	/**
	 * Generate GetMethod to proxy
	 * 
	 * @param request
	 * @param response
	 * @param requestURL
	 * 
	 * @return
	 * 
	 * @throws UnsupportedEncodingException
	 */
	private HttpMethod generateGetMethod(HttpServletRequest request,
			HttpServletResponse response, String requestURL)
			throws UnsupportedEncodingException {
		String decodedURL = URLDecoder.decode(requestURL, "UTF-8");
		StringBuffer getUrl = new StringBuffer(
				decodedURL.replaceAll(" ", "%20"));
		GetMethod method = new GetMethod(getUrl.toString());

		return method;
	}

	private boolean hasText(String string) {
		return string != null && string.length() > 0 && !string.isEmpty()
				&& !string.equals("");
	}

	/**
	 * Get the http client for get
	 */
	private HttpClient getHttpClient(String requestURL) {

		HttpClient httpClient = new HttpClient();

		if (this.proxyOn && !isSkipped(requestURL)) {
			if (isFullAuthentication(requestURL)) {
				httpClient.getParams().setAuthenticationPreemptive(true);
			}
			httpClient.getState().setCredentials(AuthScope.ANY,
					new UsernamePasswordCredentials(proxyUser, proxyPassword));
		}

		return httpClient;
	}

	/**
	 * Check if requestURL is starts with some noProxied String
	 * 
	 * @param requestURL
	 * 
	 * @return true if starts or false otherwise
	 */
	private boolean isSkipped(String requestURL) {
		return isIn(requestURL, noProxied);
	}

	/**
	 * Check if requestURL is starts with some fullAuthentication String
	 * 
	 * @param requestURL
	 * 
	 * @return true if starts or false otherwise
	 */
	private boolean isFullAuthentication(String requestURL) {
		return isIn(requestURL, fullAuthentication);
	}

	/**
	 * Check if string is starts with some posibilities String array
	 * 
	 * @param string
	 * 
	 * @return true if starts or false otherwise
	 */
	private boolean isIn(String string, String[] posibilities) {
		if (posibilities != null && posibilities.length > 0) {
			for (String posibilty : posibilities) {
				if (string.startsWith(posibilty)) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * URL filtering urls not in authorizedUrls are avoid
	 * 
	 * @param url
	 * @param request
	 * 
	 * @return <code>String</code> target url with parameters
	 */
	private String manageUrl(String url, HttpServletRequest request,
			HttpServletResponse response) throws Exception {

		String header = request.getHeader("X-Forwarded-Host");
		if (header != null) {
			header = new StringTokenizer(header, ",").nextToken().trim();
		}
		if (header == null) {
			header = request.getHeader("Host");
		}

		// if (//log.isTraceEnabled()) {
		// log.trace("Previus url : " + url);
		// log.trace("Filtering from Base url: " + localUrl);
		// }
		// ¿Is avoid?
		boolean found = false;
		String result = url;
		Iterator<String> itKies = authorizedUrls.keySet().iterator();
		if (MUST_CHECK_URL) {
			while (itKies.hasNext() && !found) {
				String key = itKies.next();
				// log.trace("Starts with '" + localUrl + "/" + key + "'?");
				if (url.contains(key)) {
					String starts = url.substring(url.indexOf(key));

					if (starts.startsWith(key)) {
						result = starts.replace(key, authorizedUrls.get(key));
						// log.trace("Url authorized");
						found = true;
					}
				}
			}
		}

		if (!found && MUST_CHECK_URL) {
			// FORBIDDEN!
			// log.warn("Url not found in authorized urls: " + url);
			response.sendError(HttpServletResponse.SC_FORBIDDEN,
					"Proxy only to local requests.");
			throw new Exception("Trying to proxy from "
					+ request.getRemoteHost());
		}

		// log.trace("Url managed: " + result);

		return result;
	}

	/**
	 * Pipes everything from the reader to the writer via a buffer
	 */
	private static void pipe(Reader reader, Writer writer) throws IOException {
		char[] buf = new char[1024];
		int read = 0;
		while ((read = reader.read(buf)) >= 0) {
			writer.write(buf, 0, read);
		}
		writer.flush();
	}

}
