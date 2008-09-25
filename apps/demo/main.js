var webapp = loadModule('helma.webapp');
var handleRequest = loadModule('helma.webapp.handler').handleRequest;
var render = loadModule('helma.skin').render;
// loadModule('helma.continuation');
var logging = loadModule('helma.logging');
logging.enableResponseLog();
var log = logging.getLogger(__name__);

var mount = {
    point: loadModule('webmodule')
}

// the main action is invoked for http://localhost:8080/
function main_action(req, res) {
    res.render('skins/index.html', { title: 'Welcome to Helma NG' });
}

// demo for skins, macros, filters
function skins_action(req, res) {
    var context = {
        title: 'Skin Demo',
        name: 'Luisa',
        names: ['Benni', 'Emma', 'Luca', 'Selma']
    };
    res.render('skins/skins.html', context);
}

// demo for log4j logging
function logging_action(req, res) {
    // make sure responselog is enabled
    var hasResponseLog = logging.responseLogEnabled();
    if (!hasResponseLog) {
        logging.enableResponseLog();
        log.debug("enabling response log");
    }
    if (req.data.info) {
        log.info("Hello world!");
    } else if (req.data.error) {
        try {
            foo.bar.moo;
        } catch (e) {
            log.error(e, e.rhinoException);
        }
    }
    res.render('skins/logging.html', { title: "Logging Demo" });
    if (!hasResponseLog) {
        log.debug("disabling response log");
        logging.disableResponseLog();
    }
    logging.flushResponseLog();
}

// demo for continuation support
function continuation_action(req, res) {

    // local data - this is the data that is shared between resuming and suspension
    var data = {};
    var pages = ["start", "name", "favorite food", "favorite animal", "result"];
    // to have only one continuation per user just give the pages fixed ids
    // var pageIds = [0, 1, 2, 3, 4];
    // to have continuations created dynamically start with empty page ids
    var pageIds = [];

    // mark start of continuation code. We never step back earlier than this
    // otherwise local data would be re-initialized
    pageIds[0] = Continuation.startId(req);
    [req, res] = Continuation.markStart(req, res, pageIds[0]);
    // render intro page
    log.info("running post makestart")
    renderPage(0);
    log.info("running first page")
    // render first page
    renderPage(1)
    // render second page
    renderPage(2);
    // render third page
    renderPage(3);
    // render overview page
    if (!data.name) renderPage(1);
    renderPage(4);

    // the local function to do the actual work
    function renderPage(id) {
        var previous = pages[id - 1]
        if (req.isPost() && previous) {
           data[previous] = req.params[previous];
        }
        if (id < pages.length - 1) {
            pageIds[id + 1] = Continuation.nextId(req, pageIds[id + 1]);
            if (id < 1) {
                res.render('skins/continuation.html', {
                    title: "Welcome",
                    skin: "start",
                    data: data,
                    forward: Continuation.getUrl(req, pageIds[id + 1])
                });
            } else {
                res.render('skins/continuation.html', {
                    title: "Question " + id,
                    skin: "mask",
                    input: pages[id],
                    data: data,
                    value: data[pages[id]],
                    back: Continuation.getUrl(req, pageIds[id - 1]),
                    forward: Continuation.getUrl(req, pageIds[id + 1])
                });
            }
            [req, res] = Continuation.nextPage(req, pageIds[id + 1]);
        } else {
            res.render('skins/continuation.html', {
                title: "Thanks!",
                skin: "result",
                data: data,
                back: Continuation.getUrl(req, pageIds[id - 1])
            });
        }
    }
}


function test_action(req, res) {
    res.buffer.write(req, req.session);
}

// main method called to start application
if (__name__ == "__main__") {
    webapp.start();
}
