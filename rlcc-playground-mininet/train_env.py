from core.rlccenv import RlccMininet, PcapAt
from mininet.log import setLogLevel
import argparse,os

setLogLevel('info')

#XQUIC_PATH = - # 应该是2rtt采样

map_c_2_rlcc_flag = {
    'h1': "1001",
    'h2': "1002",
    #'c3': "1003",
   # 'c4': "1004",
   # 'c5': "1005",
    #'c6': "1006",
    #'c7': "1007",
    #'c8': "1008",
    #'c9': "1009",
    #'c10': "1010",
}

pcaplist = [
    PcapAt('h1', ['ser1'], ['8443'])
]
def get_args():
        cwd = os.getcwd()
        default_logs = os.path.join(cwd, 'logs')
        default_pcaps = os.path.join(cwd, 'pcaps')
        parser = argparse.ArgumentParser()
        parser.add_argument('-q', '--quiet', help='Suppress log messages.',
                        action='store_true', required=False, default=False)
        parser.add_argument('-t', '--topo', help='Path to topology json',
                        type=str, required=False, default='./topology.json')
        parser.add_argument('-l', '--log-dir', type=str, required=False, default=default_logs)
        parser.add_argument('-p', '--pcap-dir', type=str, required=False, default=default_pcaps)
        parser.add_argument('-j', '--switch_json', type=str, required=False)
        parser.add_argument('-b', '--behavioral-exe', help='Path to behavioral executable',
                                type=str, required=False, default='simple_switch')
        return parser.parse_args()
    
    
if __name__ == '__main__':
    # from mininet.log import setLogLevel
    # setLogLevel("info")

    args = get_args()
    print("==========================")
    print(f"pcap_dir: {args.pcap_dir}")
    print(f"log-dir: {args.log_dir}")
    Exp = RlccMininet( map_c_2_rlcc_flag,args.topo, args.switch_json, args.log_dir, args.pcap_dir,args.quiet,args.behavioral_exe)

    Exp.run_train("random")   
    #Exp.cli()
    
    
