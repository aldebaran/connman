import sys
import dbus

bus = dbus.SystemBus()

provision = dbus.Interface(bus.get_object("net.connman", "/"),
					"net.connman.Provision")
creds = dict()
creds["Name"] = dbus.String("Memory", variant_level=1)
creds["EAP"] = dbus.String("peap", variant_level=1)
creds["Phase2"] = dbus.String("MSCHAPv2", variant_level=1)
creds["Identity"] = dbus.String("John", variant_level=1)
creds["Passphrase"] = dbus.String("Doe", variant_level=1)

provision.Set(creds)

print provision.Get("Memory")

print provision.List()
print provision.Del("Memory")
print provision.List()
