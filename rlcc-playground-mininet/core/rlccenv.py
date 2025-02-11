import sys, os, json
sys.path.append('/home/test/.local/lib/python3.8/site-packages')
import time
from .topo import multiTopo,ExerciseTopo
from mininet.net import Mininet
from mininet.node import Node
from mininet.cli import CLI
import random
from redis.client import Redis
from .utils import cmd_at, traffic_shaping, xquic_command, generate_xquic_tls,\
    tcpdump_command, kill_pid_by_name
from mininet.util import info
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from .p4_mininet import P4Host, P4Switch
from .p4runtime_switch import P4RuntimeSwitch
from mininet.link import TCLink
from time import sleep
from .p4runtime_lib import simple_controller
import subprocess


@dataclass
class PcapAt:
    host: str
    aim_hosts: list
    aim_ports: list
    
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


class RlccMininet:
    def __init__(self,
                 map_c_2_rlcc_flag: dict,
                 topo_file,
                 switch_json,
                 log_dir, 
                 pcap_dir,
                 quiet=False,
                 bmv2_exe='simple_switch', 
                 XQUIC_PATH='/home/test/xquic_forrlcc/build',
                 root_ip='10.0.3.3/31',
                 root_routes=['10.0.3.2/24'],
                 redis_ip='0.0.0.0',
                 redis_port=6379,
                 ) -> None:
        """
        map_c_2_rlcc_flag : dict 'clientname' : 'rlccflag'
        Topo : Train Topo
        root_ip : link to root interface
        root_route : route of root interface
        """
        self.quiet = quiet
        self.logger('Reading topology file.')
        with open(topo_file, 'r') as f:
            topo = json.load(f)
        self.hosts = topo['hosts']
        self.switches = topo['switches']
        self.links = self.parse_links(topo['links'])
        for dir_name in [log_dir, pcap_dir]:
            if not os.path.isdir(dir_name):
                if os.path.exists(dir_name):
                    raise Exception("'%s' exists and is not a directory!" % dir_name)
                os.mkdir(dir_name)
        self.log_dir = log_dir
        self.pcap_dir = pcap_dir

        # Ensure all the needed directories exist and are directories
        self.switch_json = switch_json
        self.bmv2_exe = bmv2_exe
        
        self.map_c_2_rlcc_flag = map_c_2_rlcc_flag
        self.map_rlcc_flag_2_c = dict(
            zip(map_c_2_rlcc_flag.values(), map_c_2_rlcc_flag.keys()))
        self.timestamp = dict(zip(map_c_2_rlcc_flag.values(), [
                              time.time() for _ in map_c_2_rlcc_flag.keys()]))
        self.Xquic_path = XQUIC_PATH

        #=============================================================
        # init lock
        self.LOCK = None
        self.init_lock()

        self.root_ip = root_ip
        self.root_routes = root_routes

        # init Redis
        info("\n*** Init Redis \n")
        self.r = Redis(host=redis_ip, port=redis_port)
        self.rp = Redis(host=redis_ip, port=redis_port)
        self.pub = self.r.pubsub()
        self.pub.subscribe('redis')

        
        # init Topo
        info("\n*** Init Mininet Topo \n")
        self.create_network()
        
        self.net.start()
        sleep(1)
        self.program_hosts()
        self.program_switches()
        sleep(1)
        
        # topo = Topo(len(self.map_c_2_rlcc_flag.keys()))
        # self.network = Mininet(topo, waitConnected=True)

        # connect to local interface
        info(f"\n*** Connect to local root node :{self.root_ip} \n")
        #self.connect_to_rootNS()

        info("\n*** Hosts addresses:\n")
        for host in self.net.hosts[1:]:
            info(host.name, host.IP(), '\n')

        for item in self.net.switches:
            info(f"*** Init bottleneck property: {item.name}\n")
            self.set_fix_env(item, ifpublish=False)

        self.pool = ThreadPoolExecutor(max_workers=len(self.net.hosts))
        
    def logger(self, *items):
        if not self.quiet:
            print(' '.join(items))
    def init_lock(self):
        """
        lock 用来限制c上开的流的个数, 有些环境会重复启动
        """
        self.LOCK = dict(zip(self.map_c_2_rlcc_flag.values(), [
            0]*len(self.map_c_2_rlcc_flag.values())))

    def set_lock(self, rlcc_flag):
        self.LOCK[rlcc_flag] = 1

    def del_lock(self, rlcc_flag):
        self.LOCK[rlcc_flag] = 0

#=================================================================================
    def parse_links(self, unparsed_links):
            """ Given a list of links descriptions of the form [node1, node2, latency, bandwidth]
                with the latency and bandwidth being optional, parses these descriptions
                into dictionaries and store them as self.links
            """
            links = []
            for link in unparsed_links:
                # make sure each link's endpoints are ordered alphabetically
                s, t, = link[0], link[1]
                if s > t:
                    s,t = t,s

                link_dict = {'node1':s,
                            'node2':t,
                            'latency':'0ms',
                            'bandwidth':None
                            }
                if len(link) > 2:
                    link_dict['latency'] = self.format_latency(link[2])
                if len(link) > 3:
                    link_dict['bandwidth'] = link[3]

                if link_dict['node1'][0] == 'h':
                    assert link_dict['node2'][0] == 's', 'Hosts should be connected to switches, not ' + str(link_dict['node2'])
                links.append(link_dict)
            return links
    def create_network(self):
        self.logger("Building mininet topology.")

        defaultSwitchClass = configureP4Switch(
                                sw_path=self.bmv2_exe,
                                json_path=self.switch_json,
                                log_console=True,
                                 pcap_dump=self.pcap_dir)

        self.topo = ExerciseTopo(self.hosts, self.switches, self.links, self.log_dir, self.bmv2_exe, self.pcap_dir)

        self.net = Mininet(topo = self.topo,
                      link = TCLink,
                      host = P4Host,
                      switch = defaultSwitchClass,
                      controller = None)

    

    def connect_to_rootNS(self):
        """Connect hosts to root namespace via switch. Starts network.
        network: Mininet() network object
        switch: switch to connect to root namespace
        ip: IP address for root namespace node
        routes: host networks to route to"""
        print("========-==========================")
        print(self.net)
        h3 = self.net.get('h3')
        intf = h3.defaultIntf()
        h3.setNamespace(None) 
        # Create a node in root namespace and link to switch
        #root = Node('root', inNamespace=False)
        #intf = self.net.addLink(root, s1, port2= 3).intf1
        #intf = self.topo.addLink(root, s1).intf1
        #root.setIP(self.root_ip, intf=intf)
       # root.setMAC('08:00:00:00:03:03', intf=intf)
        
        # Start network that now includes link to root namespace
        self.net.start()
        # Add routes from root ns to hosts
        # for route in self.root_routes:
        #     #root.cmd('route add -net ' + route + ' dev ' + str(intf))
        #     root.cmd('route add default gw ' + route + ' dev ' + str(intf))
        # root.cmd('arp -i eth0 -s 10.0.3.2 08:00:00:00:03:00')
        sleep(1)
        self.program_hosts()
        self.program_switches()
        sleep(1)
        
        
    def program_hosts(self):
        """ Execute any commands provided in the topology.json file on each Mininet host
        """
        for host_name, host_info in list(self.hosts.items()):
            h = self.net.get(host_name)
            if "commands" in host_info:
                for cmd in host_info["commands"]:
                    h.cmd(cmd)
    def program_switches(self):
        """ This method will program each switch using the BMv2 CLI and/or
            P4Runtime, depending if any command or runtime JSON files were
            provided for the switches.
        """
        for sw_name, sw_dict in self.switches.items():
            if 'cli_input' in sw_dict:
                self.program_switch_cli(sw_name, sw_dict)
            if 'runtime_json' in sw_dict:
                self.program_switch_p4runtime(sw_name, sw_dict)
                
    def program_switch_p4runtime(self, sw_name, sw_dict):
        """ This method will use P4Runtime to program the switch using the
            content of the runtime JSON file as input.
        """
        sw_obj = self.net.get(sw_name)
        grpc_port = sw_obj.grpc_port
        device_id = sw_obj.device_id
        runtime_json = sw_dict['runtime_json']
        self.logger('Configuring switch %s using P4Runtime with file %s' % (sw_name, runtime_json))
        with open(runtime_json, 'r') as sw_conf_file:
            outfile = '%s/%s-p4runtime-requests.txt' %(self.log_dir, sw_name)
            simple_controller.program_switch(
                addr='127.0.0.1:%d' % grpc_port,
                device_id=device_id,
                sw_conf_file=sw_conf_file,
                workdir=os.getcwd(),
                proto_dump_fpath=outfile,
                runtime_json=runtime_json
            )

    def set_random_env(self, switch, rlcc_flag=None, ifpublish=True):
        """
        set random env to link
        """
        e1 = random.randrange(0, 10)
        e2 = random.randrange(0, 10)
        rate = f'{random.randrange(5,100)}Mbit'
        buffer = f'{random.randrange(1400,2000)}b'
        # delay = f'{random.randrange(5,400)}ms' if e > 7 else \
        #     f'{random.randrange(5,100)}ms'
        # loss = f'{random.randrange(0,200)/10}%' if e > 7 else '0%'
        delay = f'{random.randrange(5,50)}ms'
        loss =  '0%'

        cmd_at(switch, traffic_shaping, ifbackend=False,
               mode='both',
               interface=switch.intfs[2].name,
               add=False,
               rate=rate,
               buffer=buffer,
               delay=delay,
               loss=loss)
        if ifpublish:
            assert rlcc_flag, "you need set valid rlccflag"
            self.rp.publish(
                'mininet', f"rlcc_flag:{rlcc_flag};bandwidth:{rate};"
                + f"rtt:{delay};loss:{loss}")

    def set_fix_env(self, switch, rlcc_flag=None, ifpublish=True,
                    rate='20Mbit',
                    buffer='1600b',
                    delay='20ms',
                    loss='0%'
                    ):
        cmd_at(switch, traffic_shaping, ifbackend=False,
               mode='both',
               interface=switch.intfs[2].name,
               add=False,
               rate=rate,
               buffer=buffer,
               delay=delay,
               loss=loss)
        if ifpublish:
            assert rlcc_flag, "you need set valid rlccflag"
            self.rp.publish(
                'mininet', f"rlcc_flag:{rlcc_flag};bandwidth:{rate};"
                + f"rtt:{delay};loss:{loss}")

    def cli(self):
        try:
            CLI(self.net)
        except:
            self.stop()

    def stop(self):
        self.net.stop()

    def run_client(self, host, ifdellock=True):
        start = time.time()
        id = int(host.name[1:])
        rlcc_flag = self.map_c_2_rlcc_flag[host.name]
        aim_server = self.net.get('h2')
        cmd_at(host, xquic_command, ifprint=False,
               type="client",
               XQUIC_PATH=self.Xquic_path,
               server_ip=aim_server.IP(),
               rlcc_flag=rlcc_flag)
        end = time.time()
    
        
        if ifdellock:  # 测试环境中，不去🔓，只跑一次测试
            self.del_lock(rlcc_flag=rlcc_flag)
        running_time = end-start
        # 运行结束，这里返回给mininet done信息， redis给mininet返回重置该路实验的信号
        self.rp.publish(
            'mininet', f"rlcc_flag:{rlcc_flag};state:done;time:"
            + f"{running_time:.2f} sec")

    def run_train(self, mode):
        """
        mode : random : random env ,
                fix   :    fix env
        """
        info("\n ---RLCC experiment start---\n")

        info("Generate key\n")
        c1 = self.net.get("h1")
        cmd_at(c1, generate_xquic_tls)
        print(c1.intf())
        info("Generate ok\n")

        info("Start xquic server\n")
        for item in [s for s in self.net.hosts if
                     s.name.startswith('h2')]:
            cmd_at(item, xquic_command, ifbackend=True,
                   type='server',
                   XQUIC_PATH=self.Xquic_path)
            info("start receive script....")
            #item.cmd('sudo python3 /home/test/xx/rlcc-playground-mininet/receive.py >> /home/test/xx/receive.txt &')
        info("Start ok\n")

        msg_stream = self.pub.listen()

        try:
            for msg in msg_stream:
                if msg["type"] == "message":
                    # notice: 第一次订阅的时候，此处会收到 mininet频道订阅的回显消息
                    # 通过rlcc_flag交互
                    rlcc_flag = str(msg["data"], encoding="utf-8")
                    if rlcc_flag == "mininet":
                        # print("订阅channel : mininet") #
                        continue
                    if rlcc_flag.endswith("stop"): # 超时主动关闭流
                        rlcc_flag = rlcc_flag[:-4]
                        host_name = self.map_rlcc_flag_2_c[rlcc_flag]
                        host = self.net.get(host_name)
                        self.del_lock(rlcc_flag)
                        print(f"{rlcc_flag}:"
                            + "steps are too long, restart the flow")
                        kill_pid_by_name("test_client")
                        
                        print("kill send script")
                        #使用 pgrep -f 查找进程（根据完整命令行匹配进程）
                        pid = subprocess.check_output(["pgrep", "-f", "/home/test/xx/rlcc-playground-mininet/send.py"]).decode().strip()
                        if pid:
                            print(f"Killing process with PID: {pid}")
                            
                            pids = pid.splitlines()
                            # 通过 kill 命令终止该进程
                            for pid in pids:
                                print(f"Killing process with PID: {pid}")
                                subprocess.call(["kill", pid])
                        else:
                            print("No process found matching the command.")
                
                    if self.LOCK[rlcc_flag] == 0:      # 收到重复消息时，由于🔓，不会重启流引发错误
                        host_name = self.map_rlcc_flag_2_c[rlcc_flag]
                        host = self.net.get(host_name)

                        host.cmd('sudo python3 /home/test/xx/rlcc-playground-mininet/send.py 10.0.2.2 "p4 is cool" > /dev/null &')
                        
                        switch = self.net.get(f"s{host_name[1:]}")
                        if mode == "random":
                            self.set_random_env(
                                switch, rlcc_flag=rlcc_flag)      # 随机重置环境
                        if mode == "fix":
                            # 固定环境测试
                            self.set_fix_env(switch, rlcc_flag=rlcc_flag)
                        print(
                            f"{rlcc_flag}:"
                            + f"{time.time()-self.timestamp[rlcc_flag]}")
                        self.timestamp[rlcc_flag] = time.time()

                        self.pool.submit(self.run_client, host,
                                         self.map_c_2_rlcc_flag)    # 开始流
                        self.set_lock(rlcc_flag=rlcc_flag)
                        print(
                            f"::start rlcc_flag: {rlcc_flag} on : {host_name}")

        except KeyboardInterrupt:
            self.rp.publish(
                'mininet', f"rlcc_flag:{self.map_c_2_rlcc_flag[host.name]};"
                + "state:stop_by_mininet")
            self.pool.shutdown()
            self.stop()

        self.stop()

    def run_exp(self, mode, pcaplist, filename=None):
        """
        mode : random : random env ,
                fix   :    fix env ,
        pcapat : list of client name

        """
        info("\n ---RLCC experiment start---\n")

        info("Generate key\n")
        c1 = self.net.get("h1")
        cmd_at(c1, generate_xquic_tls)
        info("Generate ok\n")

        info("Start xquic server\n")
        for item in [s for s in self.net.hosts if
                     s.name.startswith('h2')]:
            cmd_at(item, xquic_command, ifbackend=True,
                   type='server',
                   XQUIC_PATH=self.Xquic_path)
        info("Start ok\n")

        for clitem in pcaplist:
            host = self.net.get(clitem.host)
            aim_ips = [self.net.get(j).IP() for j in clitem.aim_hosts]
            cmd_at(host, tcpdump_command, ifbackend=True,
                   aim_ips=aim_ips,
                   ports=clitem.aim_ports)

        msg_stream = self.pub.listen()

        try:
            for msg in msg_stream:
                if msg["type"] == "message":
                    # notice: 第一次订阅的时候，此处会收到 mininet频道订阅的回显消息
                    # 通过rlcc_flag交互
                    rlcc_flag = str(msg["data"], encoding="utf-8")
                    if rlcc_flag == "mininet":
                        # print("订阅channel : mininet") #
                        continue
                    if rlcc_flag.endswith("stop"): # 超时主动关闭流
                        rlcc_flag = rlcc_flag[:-4]
                        host_name = self.map_rlcc_flag_2_c[rlcc_flag]
                        host = self.net.get(host_name)
                        self.del_lock(rlcc_flag)
                        print(f"{rlcc_flag}:"
                            + "steps are too long, restart the flow")
                        kill_pid_by_name("test_client")
                        # 停止 send.py 脚本
                        print("Stopping send.py script on host...")
                        host.cmd('sudo pkill -f "/home/test/xx/rlcc-playground-mininet/send.py 10.0.2.2"')

                    if self.LOCK[rlcc_flag] == 0:      # 收到重复消息时，由于🔓，不会重启流引发错误
                        host_name = self.map_rlcc_flag_2_c[rlcc_flag]
                        host = self.net.get(host_name)
                        switch = self.net.get(f"sw{host_name[1:]}")
                        if mode == "random":
                            self.set_random_env(
                                switch, rlcc_flag=rlcc_flag)      # 随机重置环境
                        if mode == "fix":
                            # 固定环境测试
                            self.set_fix_env(switch, rlcc_flag=rlcc_flag)
                        print(
                            f"{rlcc_flag}:"
                            + f"{time.time()-self.timestamp[rlcc_flag]}")
                        self.timestamp[rlcc_flag] = time.time()

                        self.pool.submit(self.run_client, host,
                                         self.map_c_2_rlcc_flag,
                                         False)    # 开始流, 测试环境不去🔓，所以只会启动一次流
                        self.set_lock(rlcc_flag=rlcc_flag)
                        print(
                            f"::start rlcc_flag: {rlcc_flag} on : {host_name}")

        except KeyboardInterrupt:
            self.rp.publish(
                'mininet', f"rlcc_flag:{self.map_c_2_rlcc_flag[host.name]};"
                + "state:stop_by_mininet")
            self.pool.shutdown()
            # 退出pcap
            for clitem in pcaplist:
                host = self.net.get(clitem.host)
                kill_pid_by_name("tcpdump")
            self.stop()

        # 退出pcap
        for clitem in pcaplist:
            host = self.net.get(clitem.host)
            kill_pid_by_name("tcpdump")

        self.stop()
    
    
    
    