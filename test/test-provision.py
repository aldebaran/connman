import sys
import dbus

bus = dbus.SystemBus()

provision = dbus.Interface(bus.get_object("net.connman", "/"),
					"net.connman.Provision")
creds = dict()
creds["Name"] = "Memory"
creds["EAP"] = "peap"
creds["Phase2"] = "MSCHAPv2"
creds["Identity"] = "John"
creds["Passphrase"] = "Doe"

provision.Set(creds)

print provision.Get("Memory")

print provision.List()
print provision.Del("Memory")
print provision.List()
