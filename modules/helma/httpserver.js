/**
 * Module for starting and stopping the jetty http server.
 */

export('Server');

// mark this module as shared between all requests
module.shared = true;
var log = require('helma/logging').getLogger(module.id);


/**
 * Create a Jetty HTTP server with the given configuration. The configuration may
 * either pass properties to be used with the default jetty.xml, or define
 * a custom configuration file.
 *
 * @param config Object a javascript object with any of the following properties,
 * with the default value in parentheses:
 * <ul>
 * <li>configFile ('config/jetty.xml')</li>
 * <li>port (8080)</li>
 * <li>host (undefined)</li>
 * </ul>
 *
 * For convenience, the constructor supports the definition of a JSGI and static
 * resource mapping in the config object using the following properties:
 * <ul>
 * <li>virtualHost (undefined)</li>
 * <li>mountpoint ('/')</li>
 * <li>staticDir ('static')</li>
 * <li>staticMountpoint ('/static')</li>
 * <li>moduleName ('config')</li>
 * <li>functionName ('app')</li>
 * </ul>
 */
function Server(config) {

    if (!(this instanceof Server)) {
        return new Server(config);
    }

    // the jetty server instance
    var jetty;
    var xmlconfig;

    function createContext(path, vhosts, enableSessions, enableSecurity) {
        var idMap = xmlconfig.getIdMap();
        var contexts = idMap.get("contexts");
        var context = new org.mortbay.jetty.servlet.Context(contexts, path, enableSessions, enableSecurity);
        if (vhosts) {
            context.setVirtualHosts(Array.isArray(vhosts) ? vhosts : [String(vhosts)]);
        }
        return context;
    }

    /**
     * Map a request path to a JSGI application.
     * Map a request path to a directory containing static resources.
     * @param {string} path a request path such as "/foo/bar" or "/"
     * @param {string|array} vhosts optional single or multiple virtual host names.
     *   A virtual host may start with a "*." wildcard.
     * @param {function|object} app a JSGI application, either as a function or an object
     *   with properties <code>moduleName</code> and <code>functionName</code> defining
     *   the application.
     *   <div><code>{ moduleName: 'config', functionName: 'app' }</code></div>
     */
    this.mapJSGIApp = function(path, vhosts, app) {
        log.info("Adding JSGI handler: " + path + " -> " + app.toSource());
        var context = createContext(path, vhosts, true, true);
        var engine = require('helma/engine').getRhinoEngine();
        var isFunction = typeof app === "function";
        var servlet = isFunction ?
                      new JsgiServlet(engine, app) :
                      new JsgiServlet(engine);
        var jpkg = org.mortbay.jetty.servlet;
        var servletHolder = new jpkg.ServletHolder(servlet);
        if (!isFunction) {
            servletHolder.setInitParameter('moduleName', config.moduleName || 'config');
            servletHolder.setInitParameter('functionName', config.functionName || 'app');
        }
        context.addServlet(servletHolder, "/*");
        if (jetty.isRunning()) {
            context.start();
        }
    };

    /**
     * Map a request path to a directory containing static resources.
     * @param {string} path a request path such as "/foo/bar" or "/"
     * @param {string|array} vhosts optional single or multiple virtual host names
     *   A virtual host may start with a "*." wildcard.
     * @param {string} dir the directory from which to serve static resources
     */
    this.mapStaticResources = function(path, vhosts, dir) {
        log.info("Adding static handler: " + path + " -> " + dir);
        var context = createContext(path, vhosts, false, true);
        var repo = getRepository(dir);
        context.setResourceBase(repo.exists() ? repo.getPath() : dir);
        var jpkg = org.mortbay.jetty.servlet;
        var servletHolder = new jpkg.ServletHolder(jpkg.DefaultServlet);
        // staticHolder.setInitParameter("aliases", "true");
        context.addServlet(servletHolder, "/*");
        if (jetty.isRunning()) {
            context.start();
        }
    };

    /**
     * Start the HTTP server.
     */
    this.start = function() {
        // start server
        jetty.start();
    };

    /**
     * Stop the HTTP server.
     */
    this.stop = function() {
        // Hack: keep jetty from creating a new shutdown hook with every new server
        java.lang.System.setProperty("JETTY_NO_SHUTDOWN_HOOK", "true");
        jetty.stop();
    };

    /**
     * Checks whether this server is currently running.
     * @returns true if the server is running, false otherwise.
     */
    this.isRunning = function() {
        return jetty != null && jetty.isRunning();
    };

    // init code
    config = config || {};
    print(config.toSource());
    var configFile = config.configFile || 'config/jetty.xml';
    var jettyconfig = getResource(configFile);
    if (!jettyconfig.exists()) {
        throw Error('Resource "' + configFile + '" not found');
    }
    var XmlConfiguration = org.mortbay.xml.XmlConfiguration;
    var JsgiServlet = org.helma.jsgi.JsgiServlet;
    jetty = new org.mortbay.jetty.Server();
    xmlconfig = new XmlConfiguration(jettyconfig.inputStream);
    // port config is done via properties
    var props = xmlconfig.getProperties();
    props.put('port', (config.port || 8080).toString());
    if (config.host) props.put('host', config.host);
    xmlconfig.configure(jetty);
    // Check for old/obsolete jetty config file
    var idMap = xmlconfig.getIdMap();
    if (idMap.get("helmaContext") || idMap.get("staticContext")) {
        throw new Error('Obsolete config/jetty.xml file detected.\nPlease remove the '
                       + 'definitions of "helmaContext" and "staticContext" '
                       + 'in file ' + jettyconfig + ' as these are now created dynamically.');
    }
    // Allow definition of app/static mappings in server config for convenience
    if (config.staticDir) {
        this.mapStaticResources(config.staticMountpoint || '/static', config.virtualHost, config.staticDir);
    }
    if (config.functionName && config.moduleName) {
        this.mapJSGIApp(config.mountpoint || '/', config.virtualHost, config);
    }

}


