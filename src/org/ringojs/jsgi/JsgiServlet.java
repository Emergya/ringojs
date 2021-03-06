/*
 *  Copyright 2009 Hannes Wallnoefer <hannes@helma.at>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.ringojs.jsgi;

import org.eclipse.jetty.continuation.ContinuationSupport;
import org.mozilla.javascript.RhinoException;
import org.ringojs.engine.RingoWorker;
import org.ringojs.engine.ScriptError;
import org.ringojs.engine.RingoConfiguration;
import org.ringojs.tools.RingoRunner;
import org.ringojs.repository.Repository;
import org.ringojs.repository.FileRepository;
import org.ringojs.repository.WebappRepository;
import org.ringojs.engine.RhinoEngine;
import org.ringojs.util.StringUtils;
import org.mozilla.javascript.Callable;

import com.emergya.persistenceGeo.utils.ProxyUtils;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;

public class JsgiServlet extends HttpServlet {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	
	private String proxyUrl;
	private int proxyPort;
	private String proxyUser;
	private String proxyPassword;
	private boolean proxyOn;
	private String [] noProxied = null; //Default null
	private String [] fullAuthentication = null; //Default null
	private String proxies = null; //Default null
	
	/**
	 * Environment parameters to load
	 */
	public static class EnvironmentParameters{
		/**
		 * Geoserver url runtime parameter
		 */
		public static String GEOSERVER_URL = "app.proxy.geoserver";
		/**
		 * Geoserver user runtime parameter
		 */
		public static String GEOSERVER_USER = "app.proxy.geoserver.username";
		/**
		 * Geoserver password runtime parameter
		 */
		public static String GEOSERVER_PASSWORD = "app.proxy.geoserver.password";
		/**
		 * Geoserver port runtime parameter
		 */
		public static String GEOSERVER_PORT = "app.proxy.geoserver.port";
		/**
		 * Geoserver port runtime parameter
		 */
		public static String NO_PROXIED = "app.proxy.geoserver.skiped";
		/**
		 * Geoserver port runtime parameter
		 */
		public static String FULL_AUTH = "app.proxy.geoserver.fullAuthentication";
		/**
		 * Geoserver port runtime parameter
		 */
		public static String AUTHORIZED_URLS = "app.proxy.geoserver.authorizedUrls";
		/**
		 * Geoserver port runtime parameter
		 */
		public static String CONFIG_PROXIES = "app.proxy.geoserver.proxies";
	}
	
    /**
     * Servlet init. Reads proxy configuration
     */
	public void init() throws ServletException {
		super.init();
		this.proxyUrl = System.getProperty(EnvironmentParameters.GEOSERVER_URL);
		this.proxyUser = System.getProperty(EnvironmentParameters.GEOSERVER_USER);
		this.proxyPassword = System.getProperty(EnvironmentParameters.GEOSERVER_PASSWORD);
		this.proxyPort = System.getProperty(EnvironmentParameters.GEOSERVER_PORT) != null ? Integer.decode(System.getProperty(EnvironmentParameters.GEOSERVER_PORT)) : 80; // default 80
		this.noProxied = System.getProperty(EnvironmentParameters.NO_PROXIED) != null ? System.getProperty(EnvironmentParameters.NO_PROXIED).split(",") : null;
		this.fullAuthentication = System.getProperty(EnvironmentParameters.FULL_AUTH) != null ? System.getProperty(EnvironmentParameters.FULL_AUTH).split(",") : null;
		this.proxies = System.getProperty(EnvironmentParameters.CONFIG_PROXIES);

        System.out.println("proxyUrl is "+ this.proxyUrl);
        System.out.println("proxyUser is "+ this.proxyUser);
        System.out.println("proxyPassword is "+ this.proxyPassword);
        System.out.println("proxyPort is "+ this.proxyPort);
        System.out.println("noProxied is "+ this.noProxied);
        System.out.println("fullAuthentication is "+ this.fullAuthentication);
        System.out.println("proxies are "+ this.proxies);

		if(this.proxyUrl != null || this.proxies != null){
			this.proxyOn = true;
		}else{
			this.proxyOn = false;
		}
	}

	/**
     * Service a request.
     */
    protected void service(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
    	
    	String urlParameter = request.getParameter("url");
    	
    	if(urlParameter != null
    			&& !isSkipped(urlParameter)){
    		//Do proxy
    		//System.out.println("Do proxy "+ urlParameter);
    		getProxy(urlParameter).process(request, response);
    	}else{
    		serviceOld(request, response);
    	}
    }

	/**
     * Obtain a runtime proxy
     * 
     * @param urlParameter
     * 
     * @return proxyInstance
     */
    private ProxyUtils getProxy(String urlParameter){
    	ProxyUtils proxy;
    	if(this.proxies != null){
			proxy = new ProxyUtils(this.proxies, fullAuthentication);
		}else{
			if(isProxyable(urlParameter)){
				proxy = new ProxyUtils(proxyUrl, proxyPort, proxyUser, proxyPassword, proxyOn, noProxied, null, fullAuthentication);
			}else{
				proxy = new ProxyUtils(proxyUrl, proxyPort, null, null, proxyOn, noProxied, null, fullAuthentication);
			}
		}
    	return proxy;
    }

    /**
     * Compare with proxy configuration
     * 
     * @param urlParameter
     * 
     * @return true if urlParameter is proxyable or false otherwise
     */
	private boolean isProxyable(String urlParameter) {
		
		String anotherUrl = (proxyUrl.split("/geoserver")[0] + ":" + proxyPort + "/geoserver");
		boolean isProxyable = urlParameter != null 
				&& (urlParameter.startsWith(proxyUrl)
						|| urlParameter.
							startsWith(proxyUrl.replaceAll(":", "%3A").replaceAll("/", "%2F"))
						|| urlParameter.
							startsWith(anotherUrl)
						|| urlParameter.
							startsWith(anotherUrl.replaceAll(":", "%3A").replaceAll("/", "%2F")));
		//System.out.println(urlParameter + (isProxyable ? "  is proxyable" : " is not proxyable"));
		return isProxyable;
	}
    
    /**
     * Skip proxy and pass to serviceOld
     * 
     * @param urlParameter
     * 
     * @return true if urlParameter start with one of this.noProxied
     */
    private boolean isSkipped(String urlParameter) {
		if(this.noProxied != null){
			return ProxyUtils.isIn(urlParameter, noProxied);
		}else{
			return false;
		}
	}

    String module;
    Object function;
    RhinoEngine engine;
    JsgiRequest requestProto;
    boolean hasContinuation = false;

    public JsgiServlet() {}

    public JsgiServlet(RhinoEngine engine) throws ServletException {
        this(engine, null);
    }

    public JsgiServlet(RhinoEngine engine, Callable callable) throws ServletException {
        this.engine = engine;
        this.function = callable;
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        // don't overwrite function if it was set in constructor
        if (function == null) {
            module = getStringParameter(config, "app-module", "main");
            function = getStringParameter(config, "app-name", "app");
        }

        if (engine == null) {
            String ringoHome = getStringParameter(config, "ringo-home", "/WEB-INF");
            String modulePath = getStringParameter(config, "module-path", "WEB-INF/app");
            String bootScripts = getStringParameter(config, "bootscript", null);
            int optlevel = getIntParameter(config, "optlevel", 0);
            boolean debug = getBooleanParameter(config, "debug", false);
            boolean production = getBooleanParameter(config, "production", false);
            boolean verbose = getBooleanParameter(config, "verbose", false);
            boolean legacyMode = getBooleanParameter(config, "legacy-mode", false);

            ServletContext context = config.getServletContext();
            Repository base = new WebappRepository(context, "/");
            Repository home = new WebappRepository(context, ringoHome);

            try {
                if (!home.exists()) {
                    home = new FileRepository(ringoHome);
                    System.err.println("Resource \"" + ringoHome + "\" not found, "
                            + "reverting to file repository " + home);
                }
                // Use ',' as platform agnostic path separator
                String[] paths = StringUtils.split(modulePath, ",");
                String[] systemPaths = {"modules", "packages"};
                RingoConfiguration ringoConfig =
                        new RingoConfiguration(home, base, paths, systemPaths);
                ringoConfig.setDebug(debug);
                ringoConfig.setVerbose(verbose);
                ringoConfig.setParentProtoProperties(legacyMode);
                ringoConfig.setStrictVars(!legacyMode && !production);
                ringoConfig.setReloading(!production);
                ringoConfig.setOptLevel(optlevel);
                if (bootScripts != null) {
                    ringoConfig.setBootstrapScripts(Arrays.asList(
                            StringUtils.split(bootScripts, ",")));
                }
                engine = new RhinoEngine(ringoConfig, null);
            } catch (Exception x) {
                throw new ServletException(x);
            }
        }

        requestProto = new JsgiRequest(engine.getScope());

        try {
            hasContinuation = ContinuationSupport.class != null;
        } catch (NoClassDefFoundError ignore) {
            hasContinuation = false;
        }
    }

    protected void serviceOld(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
    	
        try {
            if (hasContinuation && ContinuationSupport
                    .getContinuation(request).isExpired()) {
                return; // continuation timeouts are handled by ringo/jsgi module
            }
        } catch (Exception ignore) {
            // continuation may not be set up even if class is available - ignore
        }
        JsgiRequest req = new JsgiRequest(request, response, requestProto,
                engine.getScope(), this);
        RingoWorker worker = engine.getWorker();
        try {
            worker.invoke("ringo/jsgi/connector", "handleRequest", module,
                    function, req);
        } catch (Exception x) {
            List<ScriptError> errors = worker.getErrors();
            boolean verbose = engine.getConfig().isVerbose();
            try {
                renderError(x, response, errors);
                RingoRunner.reportError(x, System.err, errors, verbose);
            } catch (Exception failed) {
                // custom error reporting failed, rethrow original exception
                // for default handling
                RingoRunner.reportError(x, System.err, errors, false);
                throw new ServletException(x);
            }
        } finally {
            worker.release();
        }
    }

    protected void renderError(Throwable t, HttpServletResponse response,
                               List<ScriptError> errors) throws IOException {
        response.reset();
        InputStream stream = JsgiServlet.class.getResourceAsStream("error.html");
        byte[] buffer = new byte[1024];
        int read = 0;
        while (true) {
            int r = stream.read(buffer, read, buffer.length - read);
            if (r == -1) {
                break;
            }
            read += r;
            if (read == buffer.length) {
                byte[] b = new byte[buffer.length * 2];
                System.arraycopy(buffer, 0, b, 0, buffer.length);
                buffer = b;
            }
        }
        String template = new String(buffer, 0, read);
        String title = t instanceof RhinoException ?
                ((RhinoException)t).details() : t.getMessage();
        StringBuilder body = new StringBuilder();
        if (t instanceof RhinoException) {
            RhinoException rx = (RhinoException) t;
            if (errors != null && !errors.isEmpty()) {
                for (ScriptError error : errors) {
                    body.append(error.toHtml());
                }
            } else {
                body.append("<p><b>").append(rx.sourceName())
                        .append("</b>, line <b>").append(rx.lineNumber())
                        .append("</b></p>");
            }
            body.append("<h3>Script Stack</h3><pre>")
                    .append(rx.getScriptStackTrace())
                    .append("</pre>");
        }
        template = template.replaceAll("<% title %>", title);
        template = template.replaceAll("<% body %>", body.toString());
        response.setStatus(500);
        response.setContentType("text/html");
        response.getWriter().write(template);
    }

    protected String getStringParameter(ServletConfig config, String name,
                                        String defaultValue) {
        String value = config.getInitParameter(name);
        return value == null ? defaultValue : value;
    }

    protected int getIntParameter(ServletConfig config, String name,
                                  int defaultValue) {
        String value = config.getInitParameter(name);
        if (value != null) {
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException nfx) {
                System.err.println("Invalid value for parameter \"" + name
                                 + "\": " + value);
            }
        }
        return defaultValue;
    }

    protected boolean getBooleanParameter(ServletConfig config, String name,
                                          boolean defaultValue) {
        String value = config.getInitParameter(name);
        if (value != null) {
            if ("true".equals(value) || "1".equals(value) || "on".equals(value)) {
                return true;
            }
            if ("false".equals(value) || "0".equals(value) || "off".equals(value)) {
                return false;
            }
            System.err.println("Invalid value for parameter \"" + name
                             + "\": " + value);
        }
        return defaultValue;
    }
}
