"""
                                  
        |-> root-eth0
        |
c1 --- sw1 --- ser1
        |
c2 --- sw2 --- ser2
        |
c3 --- sw3 --- ser3

"""

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink
from .p4_mininet import P4Host, P4Switch
from .p4runtime_switch import P4RuntimeSwitch



def configureP4Switch(**switch_args):
    """ Helper class that is called by mininet to initialize
        the virtual P4 switches. The purpose is to ensure each
        switch's thrift server is using a unique port.
    """
    if "sw_path" in switch_args and 'grpc' in switch_args['sw_path']:
        # If grpc appears in the BMv2 switch target, we assume will start P4Runtime
        class ConfiguredP4RuntimeSwitch(P4RuntimeSwitch):
            def __init__(self, *opts, **kwargs):
                kwargs.update(switch_args)
                P4RuntimeSwitch.__init__(self, *opts, **kwargs)

            def describe(self):
                print("%s -> gRPC port: %d" % (self.name, self.grpc_port))

        return ConfiguredP4RuntimeSwitch
    else:
        class ConfiguredP4Switch(P4Switch):
            next_thrift_port = 9090
            def __init__(self, *opts, **kwargs):
                global next_thrift_port
                kwargs.update(switch_args)
                kwargs['thrift_port'] = ConfiguredP4Switch.next_thrift_port
                ConfiguredP4Switch.next_thrift_port += 1
                P4Switch.__init__(self, *opts, **kwargs)

            def describe(self):
                print("%s -> Thrift port: %d" % (self.name, self.thrift_port))

        return ConfiguredP4Switch

class ExerciseTopo(Topo):
    """ The mininet topology class for the P4 tutorial exercises.
    """
    def __init__(self, hosts, switches, links, log_dir, bmv2_exe, pcap_dir, **opts):
        Topo.__init__(self, **opts)
        host_links = []
        switch_links = []

        # assumes host always comes first for host<-->switch links
        for link in links:
            if link['node1'][0] == 'h':
                host_links.append(link)
            else:
                switch_links.append(link)

        for sw, params in switches.items():
            if "program" in params:
                switchClass = configureP4Switch(
                        sw_path=bmv2_exe,
                        json_path=params["program"],
                        log_console=True,
                        pcap_dump=pcap_dir)
            else:
                # add default switch
                switchClass = None
            self.addSwitch(sw, log_file="%s/%s.log" %(log_dir, sw), cls=switchClass)

        for link in host_links:
            host_name = link['node1']
            sw_name, sw_port = self.parse_switch_node(link['node2'])
            host_ip = hosts[host_name]['ip']
            host_mac = hosts[host_name]['mac']
            if host_name == 'h3':
                self.addHost(host_name, ip=host_ip, mac=host_mac, inNamespace=False)
            else:
                # 否则，正常添加主机
                self.addHost(host_name, ip=host_ip, mac=host_mac)
            

            self.addLink(host_name, sw_name,
                         delay=link['latency'], bw=link['bandwidth'],
                         port2=sw_port)

        for link in switch_links:
            sw1_name, sw1_port = self.parse_switch_node(link['node1'])
            sw2_name, sw2_port = self.parse_switch_node(link['node2'])
            self.addLink(sw1_name, sw2_name,
                        port1=sw1_port, port2=sw2_port,
                        delay=link['latency'], bw=link['bandwidth'])


    def parse_switch_node(self, node):
        assert(len(node.split('-')) == 2)
        sw_name, sw_port = node.split('-')
        try:
            sw_port = int(sw_port[1:])
        except:
            raise Exception('Invalid switch node in topology file: {}'.format(node))
        return sw_name, sw_port



    



class multiTopo(Topo):
    "Simple topology with multiple links"

    def build(self, n, **_kwargs):

        # while use root-eth0, 10.0.0.1 cant be used, so set a useless client
        self.addHost('c0')
        # sw0 = self.addSwitch( 'sw0' )
        # self.addLink( c0 ,sw0 )

        switchlist = []
        for i in range(n):
            si, ci = self.addHost(f'ser{i+1}'), self.addHost(f'c{i+1}')
            swi = self.addSwitch(f'sw{i+1}')
            self.addLink(ci, swi)
            self.addLink(swi, si)
            switchlist.append(swi)

        for item in switchlist[1:]:
            self.addLink(switchlist[0], item)


if __name__ == '__main__':
    setLogLevel('info')
    runMultiLink()
