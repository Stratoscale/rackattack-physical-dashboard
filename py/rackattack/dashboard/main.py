import logging
import argparse
import realtimewebui.config
import os


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

parser = argparse.ArgumentParser()
parser.add_argument("--webPort", type=int, default=6001)
parser.add_argument("--webSocketPort", type=int, default=6002)
parser.add_argument("--realtimewebuiRoot")
parser.add_argument("--dashboardRoot")
parser.add_argument("--localhostRackattackProvider", action='store_true')
parser.add_argument("--localhostRackattackProviderName", type=str, default="Local")
parser.add_argument("--rackattackInstances", type=str)
args = parser.parse_args()

if args.realtimewebuiRoot is not None:
    realtimewebui.config.REALTIMEWEBUI_ROOT_DIRECTORY = args.realtimewebuiRoot

dashboardSources = list()
if args.localhostRackattackProvider:
    dashboardSources.append(dict(name=args.localhostRackattackProviderName, host="localhost"))
if args.rackattackInstances:
    dashboardSources.extend(dict(zip(("name", "host"), provider.split(":")))
                            for provider in args.rackattackInstances.split(','))
else:
    raise Exception("Please define one or more rackattack instances")


logging.info("Rackattack instances: %(dashboardSources)s", dict(dashboardSources=dashboardSources))


from realtimewebui import server
from realtimewebui import rootresource
from realtimewebui import render
from rackattack.dashboard import pollthread
from twisted.web import static


pollThreads = list()
for dashboardSource in dashboardSources:
    logging.info("Creating poll thread for %(dashboardSource)s",
                 dict(dashboardSource=dashboardSource["name"]))
    pollThreads.append(pollthread.PollThread(dashboardSource["name"], dashboardSource["host"]))

render.addTemplateDir(os.path.join(args.dashboardRoot, 'html'))
render.DEFAULTS['title'] = "Rackattack"
render.DEFAULTS['brand'] = "Rackattack"
render.DEFAULTS['mainMenu'] = []
render.DEFAULTS["useStyleTheme"] = True
render.DEFAULTS['dashboardSources'] = dashboardSources
root = rootresource.rootResource()
root.putChild("js", static.File(os.path.join(args.dashboardRoot, "js")))
root.putChild("static", static.File(os.path.join(args.dashboardRoot, "static")))
root.putChild("favicon.ico", static.File(os.path.join(args.dashboardRoot, "static", "favicon.ico")))
root.putChild("wallboard", rootresource.Renderer("index-wallboard.html", {}))
root.putChild("seriallogs", static.File("/var/lib/rackattackphysical/seriallogs"))
for dashboardSource in dashboardSources:
    root.putChild(dashboardSource["name"],
                  rootresource.Renderer("index.html", dict(defaultDashboard=dashboardSource["name"])))
server.runUnsecured(root, args.webPort, args.webSocketPort)
