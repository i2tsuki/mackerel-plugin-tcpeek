## Usage
### Tcpeek
``` sh
systemctl start tcpeek@eth1.service 
systemctl start tcpeek@eth2.service 
```

### Mackerel plugin tcpeek
``` sh
MACKEREL_AGENT_PLUGIN_META=1 /usr/bin/mackerel_plugin_tcpeek -socket unix:///var/run/tcpeek/tcpeek_eth1.sock -metric-key-prefix tcpeek_eth1
MACKEREL_AGENT_PLUGIN_META=1 /usr/bin/mackerel_plugin_tcpeek -socket unix:///var/run/tcpeek/tcpeek_eth2.sock -metric-key-prefix tcpeek_eth2
```
