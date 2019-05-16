import miniupnpc

upnp = miniupnpc.UPnP()

upnp.discoverdelay = 10
upnp.discover()

upnp.selectigd()

port = 443

upnp.addportmapping(port, 'TCP', upnp.lanaddr, port, 'protectMeVPN','')
